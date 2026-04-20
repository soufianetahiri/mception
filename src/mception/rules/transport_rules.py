"""Transport / auth rules — static checks on how a server exposes its network surface."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity


_NETWORK_HOSTS = {"0.0.0.0", "::", "[::]"}
_REMOTE_TRANSPORTS = {"sse", "streamable-http", "streamable_http", "http"}


def rule_remote_transport_no_auth(workdir: Path) -> Iterable[Finding]:
    """If server runs over a remote transport, check for auth middleware presence."""
    remote_files: list[tuple[Path, str, ast.Call]] = []
    auth_seen = False

    for p in workdir.rglob("*.py"):
        if any(s in p.parts for s in (".git", ".venv", "venv", "__pycache__", "tests")):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (SyntaxError, OSError):
            continue

        # Detect FastMCP.run(transport=...) with non-stdio.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if _is_attr_call(node, "run"):
                    t = _kwarg_str(node, "transport") or _positional_str(node, 0)
                    if t and t.lower() in _REMOTE_TRANSPORTS:
                        remote_files.append((p, t, node))
                if _is_attr_call(node, "add_middleware") or _is_attr_call(node, "mount"):
                    auth_seen = auth_seen or _looks_auth(node, src)
                if _is_attr_call(node, "dependency_overrides"):
                    auth_seen = True

        # Cheap regex signals that auth is probably wired up somewhere.
        if re.search(r"(Bearer|OAuth|PKCE|HTTPBearer|APIKeyHeader|verify_token|verify_jwt)", src):
            auth_seen = True

    if not remote_files:
        return []

    if auth_seen:
        return []

    p, transport, call = remote_files[0]
    return [
        Finding(
            rule_id="MCP-AUTH-001",
            title=f"Remote transport ({transport}) without visible auth",
            category=Category.AUTH,
            severity=Severity.CRITICAL,
            confidence=Confidence.LIKELY,
            description=(
                f"Server runs over `{transport}` but no authentication middleware / bearer / "
                "OAuth / PKCE / APIKeyHeader is visible in the source. Remote MCP servers "
                "exposed without auth are routinely found on the public internet."
            ),
            remediation=(
                "Require OAuth 2.1 with PKCE or a bearer token for every request on remote "
                "transports. Bind session IDs to the authenticated principal."
            ),
            evidence=[Evidence(location=f"{p}:{getattr(call, 'lineno', 0)}")],
            cwe=["CWE-306", "CWE-287"],
            owasp_mcp="MCP02:2025",
            references=[
                "https://modelcontextprotocol.io/docs/tutorials/security/authorization",
                "https://www.bitsight.com/blog/exposed-mcp-servers-reveal-new-ai-vulnerabilities",
                "https://authzed.com/blog/timeline-mcp-breaches",
            ],
        )
    ]


def rule_bind_all_interfaces(workdir: Path) -> Iterable[Finding]:
    """uvicorn.run(..., host='0.0.0.0') or app.listen('0.0.0.0', ...) without auth."""
    findings: list[Finding] = []
    for p in workdir.rglob("*.py"):
        if any(s in p.parts for s in (".git", ".venv", "venv", "__pycache__", "tests")):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src)
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            host = _kwarg_str(node, "host") or _positional_str(node, 0)
            if host in _NETWORK_HOSTS:
                findings.append(
                    Finding(
                        rule_id="MCP-AUTH-002",
                        title="Server binds to all interfaces (0.0.0.0)",
                        category=Category.TRANSPORT,
                        severity=Severity.HIGH,
                        confidence=Confidence.LIKELY,
                        description=(
                            "A network bind to `0.0.0.0` exposes the server on every interface, "
                            "including external networks in many deployment contexts."
                        ),
                        remediation=(
                            "Bind to 127.0.0.1 by default; only expose externally when the "
                            "operator explicitly opts in and auth is configured."
                        ),
                        evidence=[Evidence(location=f"{p}:{getattr(node, 'lineno', 0)}")],
                        cwe=["CWE-668"],
                        owasp_mcp="MCP02:2025",
                        references=[
                            "https://cardinalops.com/blog/mcp-defaults-hidden-dangers-of-remote-deployment/",
                        ],
                    )
                )
    return findings


def rule_weak_transport_config(workdir: Path) -> Iterable[Finding]:
    """Check for common TLS misconfig patterns in Python."""
    findings: list[Finding] = []
    for p in workdir.rglob("*.py"):
        if any(s in p.parts for s in (".git", ".venv", "venv", "__pycache__", "tests")):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "verify=False" in src or "InsecureRequestWarning" in src:
            findings.append(
                Finding(
                    rule_id="MCP-AUTH-003",
                    title="TLS verification disabled",
                    category=Category.TRANSPORT,
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    description=(
                        "`verify=False` disables TLS certificate validation; any MITM on the "
                        "wire can read or tamper with traffic."
                    ),
                    remediation="Remove verify=False; use a proper CA bundle.",
                    evidence=[Evidence(location=str(p))],
                    cwe=["CWE-295"],
                    references=[
                        "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices",
                    ],
                )
            )
        if re.search(r"ssl_context\s*=\s*ssl\._create_unverified_context", src):
            findings.append(
                Finding(
                    rule_id="MCP-AUTH-003",
                    title="Unverified SSL context used",
                    category=Category.TRANSPORT,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="ssl._create_unverified_context disables hostname and cert validation.",
                    remediation="Use ssl.create_default_context().",
                    evidence=[Evidence(location=str(p))],
                    cwe=["CWE-295"],
                )
            )
    return findings


# helpers


def _is_attr_call(call: ast.Call, attr: str) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr == attr


def _kwarg_str(call: ast.Call, key: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _positional_str(call: ast.Call, idx: int) -> str | None:
    if idx < len(call.args):
        v = call.args[idx]
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            return v.value
    return None


def _looks_auth(call: ast.Call, src: str) -> bool:
    # Cheap: scan the raw source once, not AST reparse.
    return bool(re.search(r"(Bearer|OAuth|APIKeyHeader|verify_token|verify_jwt)", src))
