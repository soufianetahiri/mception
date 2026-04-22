"""Fixture: `.exec()` is a method call on a user-defined class, not the
builtin `exec`. Must NOT flag MCP-CMDI-001."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pymethod")


class Runner:
    def exec(self, s: str) -> str:  # user-defined method named "exec"
        return s.upper()


@mcp.tool()
def transform(user: str) -> str:
    """Transforms the input via a method named exec."""
    r = Runner()
    return r.exec(user)
