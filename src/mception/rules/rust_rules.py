"""Minimal regex-based SAST rules for Rust MCP servers.

Rust ecosystem is smaller + memory-safe by default, so we focus on the few
pattern classes that are *actually* dangerous: Command spawning through a
shell, reqwest to dynamic URLs, std::fs on a dynamic path.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity

RUST_EXTS = (".rs",)
_SKIP_DIRS = {".git", "target", "vendor"}


def _rust_sources(root: Path):
    for p in root.rglob("*.rs"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _line(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


# ---------- command injection ----------

_SHELL_NEW_RX = re.compile(
    r"""Command::new\s*\(\s*"(sh|bash|zsh|cmd|cmd\.exe)"\s*\)""",
)
_SHELL_FLAG_RX = re.compile(r"""\.arg\s*\(\s*"(-c|/C|/c)"\s*\)""")


def rust_rule_shell_command(path: Path, src: str, root: Path) -> Iterable[Finding]:
    m = _SHELL_NEW_RX.search(src)
    if not m:
        return []
    # Also confirm there's a -c/-C argument anywhere in the same file.
    if not _SHELL_FLAG_RX.search(src):
        return []
    return [
        Finding(
            rule_id="RUST-CMDI-001",
            title='Rust Command spawning a shell (sh -c / cmd /c)',
            category=Category.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.LIKELY,
            description=(
                "std::process::Command::new(\"sh\") / cmd followed by arg(\"-c\") is a shell "
                "invocation. Any subsequent arg assembled from user input becomes a shell command."
            ),
            remediation=(
                "Use Command::new(\"executable\").args([\"--flag\", validated_arg]) with a fixed "
                "executable and literal flags. Validate user input against an allowlist."
            ),
            evidence=[
                Evidence(
                    location=f"{_rel(path, root)}:{_line(src, m.start())}",
                    snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:220],
                )
            ],
            cwe=["CWE-78"],
            owasp_mcp="MCP05:2025",
        )
    ]


# ---------- SSRF ----------

_REQWEST_RX = re.compile(
    r"""reqwest\s*::\s*(?:blocking\s*::)?(?:get|Client::new\(\)\s*\.\s*(?:get|post|request))\s*\(""",
)


def rust_rule_ssrf(path: Path, src: str, root: Path) -> Iterable[Finding]:
    m = _REQWEST_RX.search(src)
    if not m:
        return []
    has_guard = bool(
        re.search(
            r"url::Url|IpAddr|ParseError|169\.254\.169\.254|is_loopback|is_private",
            src,
        )
    )
    return [
        Finding(
            rule_id="RUST-SSRF-001",
            title="reqwest call — confirm host allowlist",
            category=Category.SSRF,
            severity=Severity.HIGH,
            confidence=Confidence.SUSPECTED if has_guard else Confidence.LIKELY,
            description=(
                "reqwest invocation found with no obvious host-allowlist / loopback / private-IP "
                "block nearby."
            ),
            remediation=(
                "Parse via url::Url, check the host; reject IpAddr::is_loopback / is_private "
                "/ link-local before calling out."
            ),
            evidence=[
                Evidence(
                    location=f"{_rel(path, root)}:{_line(src, m.start())}",
                    snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:220],
                )
            ],
            cwe=["CWE-918"],
            owasp_mcp="MCP07:2025",
        )
    ]


def scan_rust_file(path: Path, src: str, workdir: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(rust_rule_shell_command(path, src, workdir))
    findings.extend(rust_rule_ssrf(path, src, workdir))
    return findings
