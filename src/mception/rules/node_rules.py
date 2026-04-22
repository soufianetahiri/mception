"""Regex-based SAST rules for Node.js / TypeScript MCP servers.

No AST; these rules scan source text with tight patterns designed to minimize
false positives on legitimate SDK wiring. Each rule emits Findings with
Confidence=Likely when a dangerous sink sees a dynamic argument, Confidence=
Suspected otherwise.

This isn't a substitute for a proper AST analysis — it's calibrated to catch
the most common bug shapes in MCP server code that AST-free scanners miss.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity
from .surface import classify_surface

NODE_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx")
_SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "out",
    "coverage",
    ".venv",
    "venv",
}

# ---------- helpers ----------


def _node_sources(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        # Skip test dirs; they're noisy and rules belong to the runtime surface.
        if any(part in ("test", "tests", "__tests__", "spec") for part in p.parts):
            continue
        if p.suffix.lower() in NODE_EXTS:
            yield p


def _line_of(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def _relocate(path: Path, workdir: Path) -> str:
    try:
        return str(path.relative_to(workdir))
    except ValueError:
        return str(path)


# ---------- rule: command injection / dynamic exec ----------

# Match child_process APIs. Two forms:
#   (a) `child_process.exec(...)` / `require("child_process").exec(...)` / `cp.exec(...)`  — captured with prefix
#   (b) bare `exec(...)` — only flag when an import binding to node's child_process exists
# The `(?<![.\w])` lookbehind kills the classic FP: `regex.exec(str)` (RegExp.prototype.exec),
# `someMatcher.exec(...)`, `foo_exec(...)`, etc.
_EXEC_FN_NAMES = "exec|execSync|execFile|execFileSync|spawn|spawnSync"
_EXEC_FN_RX = re.compile(
    rf"(?<![.\w])(?:(?P<prefix>child_process\s*\.\s*))?(?P<fn>{_EXEC_FN_NAMES})\s*\(",
)
# Detect whether the file binds any of those names from node's child_process module.
# Covers: ESM named imports, CJS destructured require, namespace imports, and default require.
_CP_BINDING_RX = re.compile(
    r"""(?x)
    # import { exec, spawn, ... } from 'node:child_process' | 'child_process'
    import\s*\{[^}]*\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\b[^}]*\}\s*
        from\s*['"](?:node:)?child_process['"]
    |
    # import cp from 'child_process'  — namespace / default
    import\s+(?:\*\s+as\s+)?[A-Za-z_$][\w$]*\s+from\s*['"](?:node:)?child_process['"]
    |
    # const { exec, spawn } = require('child_process')
    require\s*\(\s*['"](?:node:)?child_process['"]\s*\)
    """
)
_SHELL_TRUE_RX = re.compile(r"\{\s*[^{}]*\bshell\s*:\s*true\b[^{}]*\}", re.DOTALL)
# Detect template-string or concatenation first-arg patterns (used after the `(`).
_DYNAMIC_STR_RX = re.compile(r"""[`'"][^`'"]*\$\{|[`'"][^`'"]*\+|\+\s*[a-zA-Z_]""")


def node_rule_command_injection(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    has_cp_binding = bool(_CP_BINDING_RX.search(src))
    surface = classify_surface(path, src, workdir)
    # child_process doesn't exist in a host-managed sandbox — any `exec`/`spawn`
    # reference is either dead code or targeting a non-Node runtime. Suppress.
    if surface == "sandbox":
        return findings
    for m in _EXEC_FN_RX.finditer(src):
        fn = m.group("fn")
        # Bare `exec(...)` with no import binding to child_process → almost certainly
        # a different `exec` (regex global, custom helper). Skip to avoid FP.
        if not m.group("prefix") and not has_cp_binding:
            continue
        start = m.end()
        # Peek into the first arg up to the matching close.
        arg = _first_call_arg(src, start)
        if arg is None:
            continue
        # Evaluate dynamism.
        is_dynamic = bool(_DYNAMIC_STR_RX.search(arg)) or (
            not (arg.strip().startswith(("'", '"')) and arg.strip().endswith(("'", '"')))
            and "`" not in arg
            and re.match(r"^[a-zA-Z_]\w*\s*$", arg.strip()) is not None
        )
        is_template_with_interp = "${" in arg
        shell_true = bool(_SHELL_TRUE_RX.search(arg))
        # Only flag exec/execSync/spawn with shell=true as shell-injectable.
        if fn in ("exec", "execSync") or shell_true:
            sev = Severity.CRITICAL if (is_dynamic or is_template_with_interp) else Severity.HIGH
            conf = (
                Confidence.LIKELY if (is_dynamic or is_template_with_interp) else Confidence.SUSPECTED
            )
            findings.append(
                Finding(
                    rule_id="NODE-CMDI-001",
                    title=f"Dynamic {fn}() — shell injection risk",
                    category=Category.COMMAND_INJECTION,
                    severity=sev,
                    confidence=conf,
                    description=(
                        f"{fn}() invokes a shell. With a template literal or concatenated "
                        "argument, any user-controlled segment becomes a shell command."
                    ),
                    remediation=(
                        "Prefer execFile / spawn with an explicit argv array and shell:false. "
                        "Validate input against an allowlist."
                    ),
                    evidence=[
                        Evidence(
                            location=f"{_relocate(path, workdir)}:{_line_of(src, m.start())}",
                            snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                        )
                    ],
                    cwe=["CWE-78", "CWE-94"],
                    owasp_mcp="MCP05:2025",
                    references=[
                        "https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/",
                        "https://www.imperva.com/blog/another-critical-rce-discovered-in-a-popular-mcp-server/",
                    ],
                )
            )
    return findings


def _first_call_arg(src: str, start: int) -> str | None:
    """Return the text between the opening `(` before `start` and a heuristic comma or `)`."""
    # start is right after an opening '('; we walk and track nesting.
    depth = 1
    in_single = in_double = in_backtick = False
    escape = False
    i = start
    arg_start = start
    while i < len(src):
        ch = src[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\":
            escape = True
            i += 1
            continue
        if not (in_double or in_backtick) and ch == "'":
            in_single = not in_single
        elif not (in_single or in_backtick) and ch == '"':
            in_double = not in_double
        elif not (in_single or in_double) and ch == "`":
            in_backtick = not in_backtick
        elif not (in_single or in_double or in_backtick):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    return src[arg_start:i]
            elif ch == "," and depth == 1:
                return src[arg_start:i]
        i += 1
    return None


# ---------- rule: eval / new Function / vm ----------

_EVAL_RX = re.compile(
    r"""(?x)
    (?<![.\w])(
        eval\s*\(
      | new\s+Function\s*\(
      | vm\s*\.\s*runIn(?:This|New)Context\s*\(
      | vm\s*\.\s*Script\s*\(
    )
    """
)


def node_rule_eval(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    surface = classify_surface(path, src, workdir)
    # In a host-managed sandbox (plugin, browser extension, editor extension,
    # edge isolate) `eval`/`Function` runs inside the sandbox, not on the user's
    # OS. It's still dangerous capability, but it's not the same as RCE on a
    # long-lived Node server — many of these runtimes use eval as their
    # intended extension mechanism. Build-tool configs execute on the
    # developer's machine at CI time, narrower blast radius than prod.
    if surface == "sandbox":
        sev, conf, surface_note = (
            Severity.MEDIUM,
            Confidence.SUSPECTED,
            " (sandbox surface — evaluated inside host-managed runtime, not a user OS process)",
        )
    elif surface == "build":
        sev, conf, surface_note = (
            Severity.LOW,
            Confidence.SUSPECTED,
            " (build-time config — runs only during bundling/tests)",
        )
    else:
        sev, conf, surface_note = Severity.CRITICAL, Confidence.LIKELY, ""
    for m in _EVAL_RX.finditer(src):
        out.append(
            Finding(
                rule_id="NODE-CMDI-002",
                title=f"Dynamic code execution via {m.group(1).strip()}{surface_note}",
                category=Category.COMMAND_INJECTION,
                severity=sev,
                confidence=conf,
                description=(
                    "Runtime evaluation APIs give any untrusted argument full code-exec authority."
                    + (
                        "\n\nExecution surface: " + surface + ". "
                        + (
                            "Code runs inside the host's managed runtime (plugin/extension/isolate), "
                            "so a malicious argument cannot spawn processes or touch the filesystem "
                            "directly — but it can still abuse the sandbox's own API surface."
                            if surface == "sandbox"
                            else "Config file executes at build/test time on developer or CI machines."
                            if surface == "build"
                            else ""
                        )
                    )
                ),
                remediation=(
                    "Remove. If a sandbox is genuinely needed, use isolated-vm or a proper "
                    "language-level interpreter — not eval/Function."
                ),
                evidence=[
                    Evidence(
                        location=f"{_relocate(path, workdir)}:{_line_of(src, m.start())}",
                        snippet=(src[m.start():m.start() + 120]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-95"],
                owasp_mcp="MCP05:2025",
                references=[
                    "https://cwe.mitre.org/data/definitions/95.html",
                ],
            )
        )
    return out


# ---------- rule: SSRF (dynamic URL to fetch/axios/http) ----------

_HTTP_CALL_RX = re.compile(
    r"""(?x)
    \b(
        fetch\s*\(
      | axios\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\(
      | axios\s*\(
      | got\s*\(
      | needle\s*\(
      | undici\s*\.\s*request\s*\(
      | http\s*\.\s*(?:get|request)\s*\(
      | https\s*\.\s*(?:get|request)\s*\(
      | request\s*\(
    )
    """
)
_HOST_ALLOWLIST_HINT_RX = re.compile(
    r"""(?x)
    \b(
      URL\s*\(|new\s+URL\s*\(
    )|
    allowlist|allow_list|allowedHosts|ALLOWED_HOSTS|blockPrivateIPs|
    169\.254\.169\.254|127\.0\.0\.1|private_ip
    """,
    re.IGNORECASE,
)


def node_rule_ssrf(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    calls = list(_HTTP_CALL_RX.finditer(src))
    if not calls:
        return []
    has_allowlist_hint = bool(_HOST_ALLOWLIST_HINT_RX.search(src))
    out: list[Finding] = []
    for m in calls:
        # Inspect first-arg dynamism.
        arg = _first_call_arg(src, m.end()) or ""
        dynamic = "${" in arg or re.search(r"\+\s*[a-zA-Z_]", arg) or re.match(
            r"^\s*[a-zA-Z_]\w*\s*$", arg
        )
        if not dynamic:
            continue
        conf = Confidence.LIKELY if not has_allowlist_hint else Confidence.SUSPECTED
        out.append(
            Finding(
                rule_id="NODE-SSRF-001",
                title="Outbound HTTP call with dynamic URL",
                category=Category.SSRF,
                severity=Severity.HIGH,
                confidence=conf,
                description=(
                    "A dynamic URL is passed to an HTTP client with no obvious allowlist / "
                    "private-IP block visible in the file. Attackers can pivot to cloud IMDS, "
                    "localhost, file://, or gopher://."
                ),
                remediation=(
                    "Parse the URL, assert scheme==https, resolve the host, reject RFC1918 "
                    "/ link-local / loopback / 169.254.169.254. Prefer a pre-approved host allowlist."
                ),
                evidence=[
                    Evidence(
                        location=f"{_relocate(path, workdir)}:{_line_of(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-918"],
                owasp_mcp="MCP07:2025",
                references=[
                    "https://www.descope.com/blog/post/mcp-vulnerabilities",
                ],
            )
        )
    return out


# ---------- rule: path traversal on fs.* ----------

_FS_PATH_RX = re.compile(
    r"""(?x)
    \bfs(?:/promises)?\s*\.\s*
    (readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream|createWriteStream|open|openSync)
    \s*\(
    """
)
_PATH_GUARD_RX = re.compile(
    r"""(?x)
    path\.resolve\s*\(|
    path\.normalize\s*\(|
    startsWith\s*\(|
    \.relative\s*\(|
    realpathSync\s*\(
    """
)


def node_rule_path_traversal(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    calls = list(_FS_PATH_RX.finditer(src))
    if not calls:
        return []
    has_guard = bool(_PATH_GUARD_RX.search(src))
    out: list[Finding] = []
    for m in calls:
        arg = _first_call_arg(src, m.end()) or ""
        dynamic = "${" in arg or re.search(r"\+\s*[a-zA-Z_]", arg) or re.match(
            r"^\s*[a-zA-Z_]\w*\s*$", arg
        )
        if not dynamic:
            continue
        conf = Confidence.SUSPECTED if has_guard else Confidence.LIKELY
        out.append(
            Finding(
                rule_id="NODE-PATH-001",
                title=f"Path traversal risk in fs.{m.group(1)}",
                category=Category.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                confidence=conf,
                description=(
                    f"fs.{m.group(1)} receives a dynamic path with no visible realpath-anchor "
                    "check. '..' / absolute paths / symlinks escape any intended root."
                ),
                remediation=(
                    "path.resolve against a fixed root, then assert the result startsWith the root. "
                    "Reject absolute paths."
                ),
                evidence=[
                    Evidence(
                        location=f"{_relocate(path, workdir)}:{_line_of(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-22"],
                owasp_mcp="MCP06:2025",
            )
        )
    return out


# ---------- rule: unsafe yaml / JSON.parse-from-untrusted ----------

_YAML_UNSAFE_RX = re.compile(
    r"""(?x)
    \byaml\s*\.\s*(load|parseDocument)\s*\(
    """
)


def node_rule_unsafe_yaml(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _YAML_UNSAFE_RX.finditer(src):
        fn = m.group(1)
        # js-yaml: load() is safe-by-default since v4, but load(x, { schema: FAILSAFE_SCHEMA }) etc may vary;
        # flag with Suspected — a human should check which yaml lib is in use.
        out.append(
            Finding(
                rule_id="NODE-DES-001",
                title=f"Potentially unsafe YAML parse: yaml.{fn}",
                category=Category.DESERIALIZATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.SUSPECTED,
                description=(
                    f"yaml.{fn} may deserialize untrusted YAML into rich objects depending on the "
                    "library / schema. Verify the library is js-yaml v4+ and no DANGER schema "
                    "option is in use, or switch to yaml.safeLoad / SAFE_SCHEMA."
                ),
                remediation="Use a safe schema and avoid parsing untrusted YAML altogether.",
                evidence=[
                    Evidence(
                        location=f"{_relocate(path, workdir)}:{_line_of(src, m.start())}",
                        snippet=(src[m.start():m.start() + 120]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-502"],
            )
        )
    return out


# ---------- rule: TLS verification disabled ----------

_TLS_OFF_RX = re.compile(
    r"""(?x)
    rejectUnauthorized\s*:\s*false
    | NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?
    """
)


def node_rule_weak_tls(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _TLS_OFF_RX.finditer(src):
        out.append(
            Finding(
                rule_id="NODE-AUTH-001",
                title="TLS verification disabled",
                category=Category.TRANSPORT,
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    "`rejectUnauthorized: false` (or NODE_TLS_REJECT_UNAUTHORIZED=0) disables "
                    "TLS certificate validation. Any MITM on the wire can read / tamper with traffic."
                ),
                remediation="Remove; provide a proper CA bundle.",
                evidence=[
                    Evidence(
                        location=f"{_relocate(path, workdir)}:{_line_of(src, m.start())}",
                        snippet=(src[m.start():m.start() + 120]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-295"],
            )
        )
    return out


# ---------- file driver ----------


def scan_node_file(path: Path, src: str, workdir: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(node_rule_command_injection(path, src, workdir))
    findings.extend(node_rule_eval(path, src, workdir))
    findings.extend(node_rule_ssrf(path, src, workdir))
    findings.extend(node_rule_path_traversal(path, src, workdir))
    findings.extend(node_rule_unsafe_yaml(path, src, workdir))
    findings.extend(node_rule_weak_tls(path, src, workdir))
    return findings
