"""Whole-config analyzer.

Reads an MCP client config file (claude_desktop_config.json / .mcp.json /
settings.json with `mcpServers`), audits each server individually, and then
applies whole-config rules:

  - Duplicate tool names across servers (tool squatting)
  - Cross-server tool mentions in descriptions (shadowing)
  - Lethal-trifecta composition (one server reads private data, another can egress)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity
from ..report import AuditReport


def load_mcp_config(config_path: Path) -> list[tuple[str, dict]]:
    """Return [(server_name, server_entry), ...]. server_entry is the raw JSON value."""
    data = json.loads(config_path.read_text(encoding="utf-8"))
    servers = (
        data.get("mcpServers")
        or data.get("mcp_servers")
        or (data.get("servers") if isinstance(data.get("servers"), dict) else None)
        or {}
    )
    if not isinstance(servers, dict):
        return []
    return list(servers.items())


def server_entry_to_target(entry: dict) -> str | None:
    """Convert an MCP config entry to a target ref mception can fetch.

    We handle the common cases:
      - {"command": "uvx", "args": ["<pypi-pkg>"]}
      - {"command": "npx", "args": ["-y", "<npm-pkg>"]}
      - {"command": "node", "args": ["./local/path/to/server.js"]}
      - {"command": "python", "args": ["./local/path/to/server.py"]}
      - {"command": "docker", "args": ["run", ..., "<image>"]} → return "docker:<image>"
      - {"url": "https://…"}    → remote; no static fetch (inconclusive)
    """
    if entry.get("url"):
        return None
    cmd = (entry.get("command") or "").lower()
    args = entry.get("args") or []
    if cmd in ("uvx", "pipx") and args:
        name = _first_non_flag(args)
        if name:
            return f"pypi:{name}"
    if cmd == "npx" and args:
        name = _first_non_flag(args)
        if name:
            return f"npm:{name}"
    if cmd in ("node", "python", "python3", "bun", "deno"):
        if args:
            # Prefer the last arg that looks like a path.
            for a in reversed(args):
                if "/" in a or "\\" in a or a.endswith((".js", ".ts", ".py", ".mjs")):
                    return str(a)
            return args[0]
    if cmd == "docker" and args:
        # Last positional is usually the image.
        for a in reversed(args):
            if not a.startswith("-"):
                return f"docker:{a}"
    return None


def _first_non_flag(args: list[str]) -> str | None:
    for a in args:
        if not a.startswith("-"):
            return a
    return None


# ---------- whole-config rules over collected AuditReports ----------


def rule_duplicate_tool_names(reports: dict[str, AuditReport]) -> list[Finding]:
    """Across all servers' extracted tool names, flag duplicates (from meta notes)."""
    # We don't have tool names in the Finding model, but we added them via engine note.
    # Easiest approach: re-derive from findings' target_component fields.
    seen: dict[str, list[str]] = {}
    for name, rep in reports.items():
        for f in rep.findings:
            # Metadata-rule locations look like: tool[read_file]@...
            tname = _extract_tool_name(f)
            if tname is None:
                continue
            seen.setdefault(tname, []).append(name)
    findings: list[Finding] = []
    for tname, servers in seen.items():
        uniq = sorted(set(servers))
        if len(uniq) > 1:
            findings.append(
                Finding(
                    rule_id="MCP-XCFG-001",
                    title=f"Duplicate tool name {tname!r} across servers",
                    category=Category.SHADOWING,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"Tool {tname!r} is registered by multiple MCP servers ({', '.join(uniq)}). "
                        "Clients can pick the wrong one — this is tool-squatting."
                    ),
                    remediation=(
                        "Namespace tool names by server, or remove the duplicate from whichever "
                        "server is least essential."
                    ),
                    evidence=[Evidence(location="config", extra={"tool": tname, "servers": uniq})],
                    cwe=["CWE-494"],
                    references=[
                        "https://acuvity.ai/cross-server-tool-shadowing-hijacking-calls-between-servers/",
                    ],
                )
            )
    return findings


def _extract_tool_name(f: Finding) -> str | None:
    for ev in f.evidence:
        m = re.match(r"tool\[([^\]]+)\]", ev.location or "")
        if m:
            return m.group(1)
    return None


def rule_lethal_trifecta(reports: dict[str, AuditReport]) -> list[Finding]:
    """Across servers, detect the read-private + write-egress shape."""
    reads_private = set()
    writes_egress = set()
    for name, rep in reports.items():
        for f in rep.findings:
            if f.category in (Category.CREDENTIAL_EXFIL, Category.PATH_TRAVERSAL):
                reads_private.add(name)
            if f.category in (Category.SSRF, Category.EXFIL_SINK):
                writes_egress.add(name)
    if not reads_private or not writes_egress:
        return []
    return [
        Finding(
            rule_id="MCP-XCFG-002",
            title="Lethal-trifecta composition across configured servers",
            category=Category.EXFIL_SINK,
            severity=Severity.HIGH,
            confidence=Confidence.SUSPECTED,
            description=(
                "Your config includes at least one server that can read private data ("
                + ", ".join(sorted(reads_private))
                + ") and at least one that can egress data ("
                + ", ".join(sorted(writes_egress))
                + "). A prompt injection anywhere in the agent can compose these."
            ),
            remediation=(
                "Do not run read-private and write-egress MCP servers in the same session unless "
                "each tool call requires explicit user approval."
            ),
            evidence=[
                Evidence(
                    location="config",
                    extra={"reads_private": sorted(reads_private), "writes_egress": sorted(writes_egress)},
                )
            ],
            cwe=["CWE-829"],
            owasp_mcp="MCP03:2025",
            references=[
                "https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/",
            ],
        )
    ]
