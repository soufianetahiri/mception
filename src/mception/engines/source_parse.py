"""Static extraction of MCP tool/resource/prompt surfaces from source code.

Strategy:
  - Python: AST walk looking for FastMCP decorator patterns
    (@<mcp>.tool(), @<mcp>.resource(uri), @<mcp>.prompt()) and the low-level
    `Server.add_tool(name=..., description=...)` calls. Docstring of the
    decorated function becomes the `description`.
  - Node/TS: regex scan for `server.addTool({ name: "...", description: "..." })`
    and inline `ListToolsRequestSchema` handlers returning `{ name, description }`
    objects. Best-effort; can miss dynamic construction.

No code is ever imported or executed.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractedItem:
    kind: str  # "tool" | "resource" | "prompt" | "server_instructions"
    name: str
    description: str | None
    source_file: Path
    line: int
    extras: dict = field(default_factory=dict)


_DECORATOR_KINDS = {"tool": "tool", "resource": "resource", "prompt": "prompt"}
_NODE_ADD_TOOL_RX = re.compile(
    r"""(?xs)
    \.addTool\s*\(\s*\{\s*
      (?:[^}]*?\bname\s*:\s*(?P<q1>['"])(?P<name>[^'"]+)(?P=q1))
      (?:[^}]*?\bdescription\s*:\s*(?P<q2>['"`])(?P<desc>(?:\\.|(?!(?P=q2)).)*)(?P=q2))?
    """,
)
_NODE_TOOL_OBJ_RX = re.compile(
    r"""(?xs)
    \{\s*
      name\s*:\s*(?P<q1>['"])(?P<name>[^'"]+)(?P=q1)\s*,
      [^{}]*?
      description\s*:\s*(?P<q2>['"`])(?P<desc>(?:\\.|(?!(?P=q2)).)*)(?P=q2)
    """,
)
_INSTRUCTIONS_RX = re.compile(
    r"""server\.instructions\s*=\s*(?P<q>['"`])(?P<text>(?:\\.|(?!(?P=q)).)*)(?P=q)"""
)


def extract_from_workdir(workdir: Path) -> list[ExtractedItem]:
    """Walk a workdir, apply language-appropriate extractors, return items found."""
    items: list[ExtractedItem] = []
    for p in _walk_source_files(workdir):
        try:
            if p.suffix == ".py":
                items.extend(_extract_python(p))
            elif p.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx"):
                items.extend(_extract_node(p))
        except (SyntaxError, UnicodeDecodeError):
            # Skip files we can't parse; don't fail the whole audit.
            continue
    return items


def _walk_source_files(root: Path):
    skip = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv"}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.parts):
            continue
        if p.suffix in (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx"):
            yield p


# ---- Python ----


def _extract_python(path: Path) -> list[ExtractedItem]:
    src = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src, filename=str(path))
    out: list[ExtractedItem] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = _decorator_mcp_kind(node)
            if kind is None:
                continue
            name = _decorator_kwarg(node, "name") or node.name
            desc = ast.get_docstring(node) or _decorator_kwarg(node, "description")
            params = _function_param_names(node)
            out.append(
                ExtractedItem(
                    kind=kind,
                    name=name,
                    description=desc,
                    source_file=path,
                    line=node.lineno,
                    extras={"params": params},
                )
            )
        elif isinstance(node, ast.Call):
            # Low-level: server.add_tool(name="x", description="y", ...)
            fn = _attr_chain(node.func)
            if fn and fn.endswith("add_tool"):
                name = _kwarg_const(node, "name") or "<unknown>"
                desc = _kwarg_const(node, "description")
                out.append(
                    ExtractedItem(
                        kind="tool",
                        name=name,
                        description=desc,
                        source_file=path,
                        line=node.lineno,
                    )
                )
        elif isinstance(node, ast.Assign):
            # server.instructions = "..."
            for t in node.targets:
                if _attr_chain(t) and _attr_chain(t).endswith(".instructions"):
                    v = _literal_str(node.value)
                    if v is not None:
                        out.append(
                            ExtractedItem(
                                kind="server_instructions",
                                name="<instructions>",
                                description=v,
                                source_file=path,
                                line=node.lineno,
                            )
                        )
    return out


def _function_param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = fn.args
    names: list[str] = []
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        if a.arg not in ("self", "cls"):
            names.append(a.arg)
    return names


def _decorator_mcp_kind(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for d in fn.decorator_list:
        attr = _decorator_attr(d)
        if attr in _DECORATOR_KINDS:
            return _DECORATOR_KINDS[attr]
    return None


def _decorator_attr(dec: ast.expr) -> str | None:
    # @mcp.tool()  or  @mcp.tool(name="x")  or  @mcp.tool
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _decorator_kwarg(fn: ast.FunctionDef | ast.AsyncFunctionDef, key: str) -> str | None:
    for d in fn.decorator_list:
        if isinstance(d, ast.Call):
            v = _kwarg_const(d, key)
            if v is not None:
                return v
    return None


def _kwarg_const(call: ast.Call, key: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == key:
            v = _literal_str(kw.value)
            if v is not None:
                return v
    return None


def _literal_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    # Implicit string concatenation / f-string "literal" with just strings.
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                return None
        return "".join(parts)
    return None


def _attr_chain(node: ast.expr | None) -> str | None:
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


# ---- Node / TypeScript (best-effort regex) ----


def _extract_node(path: Path) -> list[ExtractedItem]:
    src = path.read_text(encoding="utf-8", errors="replace")
    out: list[ExtractedItem] = []

    for m in _NODE_ADD_TOOL_RX.finditer(src):
        out.append(
            ExtractedItem(
                kind="tool",
                name=m.group("name"),
                description=_unescape(m.group("desc")) if m.group("desc") else None,
                source_file=path,
                line=src[: m.start()].count("\n") + 1,
            )
        )

    for m in _INSTRUCTIONS_RX.finditer(src):
        out.append(
            ExtractedItem(
                kind="server_instructions",
                name="<instructions>",
                description=_unescape(m.group("text")),
                source_file=path,
                line=src[: m.start()].count("\n") + 1,
            )
        )
    # Fallback: objects with name + description in handler returns.
    # Only used when we found zero addTool hits (to avoid double-counting).
    if not any(_NODE_ADD_TOOL_RX.finditer(src)):
        for m in _NODE_TOOL_OBJ_RX.finditer(src):
            out.append(
                ExtractedItem(
                    kind="tool",
                    name=m.group("name"),
                    description=_unescape(m.group("desc")),
                    source_file=path,
                    line=src[: m.start()].count("\n") + 1,
                )
            )
    return out


def _unescape(s: str) -> str:
    # Cheap JS string-escape unescape: covers \n, \t, \\, \', \", \`.
    return (
        s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\'", "'")
        .replace('\\"', '"')
        .replace("\\`", "`")
        .replace("\\\\", "\\")
    )
