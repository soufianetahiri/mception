"""Tests for the AST-based source parser."""

from __future__ import annotations

from pathlib import Path

from mception.engines.source_parse import extract_from_workdir


def test_fastmcp_decorator_extracted(tmp_path: Path):
    (tmp_path / "server.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
async def read_file(path: str) -> str:
    """Read a file and return its contents."""
    return open(path).read()

@mcp.resource("x://thing")
def thing_resource() -> str:
    """Something."""
    return "x"

@mcp.prompt()
def checklist() -> str:
    """Prompt docstring here."""
    return "ok"
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    kinds = sorted({i.kind for i in items})
    assert "tool" in kinds and "resource" in kinds and "prompt" in kinds
    tool = next(i for i in items if i.kind == "tool")
    assert tool.name == "read_file"
    assert "Read a file" in (tool.description or "")


def test_server_instructions_extracted(tmp_path: Path):
    (tmp_path / "s.py").write_text(
        'server.instructions = "You are a helpful assistant."\n', encoding="utf-8"
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.kind == "server_instructions" for i in items)


def test_node_addtool_regex(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        '''
server.addTool({
  name: "do_thing",
  description: "Does a thing.",
  inputSchema: { type: "object" },
});
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert items and items[0].kind == "tool" and items[0].name == "do_thing"


def test_skips_ignored_dirs(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "fake.js").write_text(
        'server.addTool({ name: "bad", description: "x" });', encoding="utf-8"
    )
    items = extract_from_workdir(tmp_path)
    assert items == []


def test_syntax_error_does_not_crash(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def oops( :\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def t():
    """ok."""
    return 1
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    names = [i.name for i in items]
    assert "t" in names
