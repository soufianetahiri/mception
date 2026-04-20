"""Transport / auth rule tests."""

from __future__ import annotations

from pathlib import Path

from mception.rules.transport_rules import (
    rule_bind_all_interfaces,
    rule_remote_transport_no_auth,
    rule_weak_transport_config,
)


def test_remote_transport_without_auth(tmp_path: Path):
    (tmp_path / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
mcp.run(transport="sse")
''',
        encoding="utf-8",
    )
    r = list(rule_remote_transport_no_auth(tmp_path))
    assert r and r[0].rule_id == "MCP-AUTH-001"


def test_remote_transport_with_auth_hint_suppressed(tmp_path: Path):
    (tmp_path / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
from fastapi.security import HTTPBearer
mcp = FastMCP("x")
token = HTTPBearer()
mcp.run(transport="streamable-http")
''',
        encoding="utf-8",
    )
    r = list(rule_remote_transport_no_auth(tmp_path))
    assert r == []


def test_stdio_transport_ignored(tmp_path: Path):
    (tmp_path / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
mcp.run(transport="stdio")
''',
        encoding="utf-8",
    )
    assert list(rule_remote_transport_no_auth(tmp_path)) == []


def test_bind_0_0_0_0(tmp_path: Path):
    (tmp_path / "s.py").write_text(
        'import uvicorn\nuvicorn.run(app, host="0.0.0.0", port=8000)\n',
        encoding="utf-8",
    )
    r = list(rule_bind_all_interfaces(tmp_path))
    assert r and r[0].rule_id == "MCP-AUTH-002"


def test_tls_verify_false(tmp_path: Path):
    (tmp_path / "s.py").write_text(
        'import requests\nresp = requests.get("https://x", verify=False)\n', encoding="utf-8"
    )
    r = list(rule_weak_transport_config(tmp_path))
    assert r and r[0].rule_id == "MCP-AUTH-003"
