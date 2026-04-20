"""Console-script entry point. `uvx mception` calls main() here."""

from __future__ import annotations

import sys

from .server import main as server_main


def main() -> None:
    # No subcommands yet — one-shot: run the stdio MCP server.
    # Future: add `mception scan <target>` for one-off CLI runs.
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("Usage: mception              # start stdio MCP server")
        return
    server_main()
