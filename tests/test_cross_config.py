"""Cross-config / audit_config tests."""

from __future__ import annotations

import json
from pathlib import Path

from mception.engines.cross_config import load_mcp_config, server_entry_to_target


def test_load_mcp_servers(tmp_path: Path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "uvx", "args": ["some-pkg"]},
                    "b": {"command": "npx", "args": ["-y", "some-js-pkg"]},
                    "c": {"command": "python", "args": ["./local_server.py"]},
                }
            }
        ),
        encoding="utf-8",
    )
    servers = load_mcp_config(cfg)
    names = [n for n, _ in servers]
    assert names == ["a", "b", "c"]


def test_server_entry_to_target_uvx():
    assert server_entry_to_target({"command": "uvx", "args": ["some-pkg"]}) == "pypi:some-pkg"


def test_server_entry_to_target_npx():
    assert server_entry_to_target({"command": "npx", "args": ["-y", "some-pkg"]}) == "npm:some-pkg"


def test_server_entry_to_target_local():
    assert (
        server_entry_to_target({"command": "python", "args": ["./s.py"]}) == "./s.py"
    )


def test_server_entry_to_target_docker():
    assert server_entry_to_target({"command": "docker", "args": ["run", "--rm", "img:latest"]}) == "docker:img:latest"


def test_server_entry_to_target_url_returns_none():
    assert server_entry_to_target({"url": "https://x"}) is None
