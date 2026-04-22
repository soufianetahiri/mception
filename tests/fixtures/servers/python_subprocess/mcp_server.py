"""Fixture: genuine subprocess.run(..., shell=True) inside a tool handler.
Must flag MCP-CMDI-001 critical."""

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pyfix")


@mcp.tool()
def list_dir(user: str) -> str:
    """Lists a user-supplied directory."""
    out = subprocess.run(f"ls {user}", shell=True, capture_output=True, text=True)
    return out.stdout
