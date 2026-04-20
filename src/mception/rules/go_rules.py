"""Regex-based SAST rules for Go MCP servers.

The Go MCP SDK at github.com/modelcontextprotocol/go-sdk (and mark3labs/mcp-go,
metoro-io/mcp-golang, etc.) register tools via builder-style calls that are
easy to pattern-match. For handler code we focus on the few sinks that
dominate real-world Go MCP vulns: os/exec, net/http client, ioutil.ReadFile,
yaml.Unmarshal, gob.Decode.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity

GO_EXTS = (".go",)
_SKIP_DIRS = {".git", "vendor", "_test", "testdata", "build"}


def _go_sources(root: Path):
    for p in root.rglob("*.go"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.name.endswith("_test.go"):
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

# exec.Command("sh", "-c", ...)  /  exec.Command(userInput, ...)
_GO_EXEC_RX = re.compile(
    r"""exec\s*\.\s*Command(?:Context)?\s*\(\s*
        (?P<prog>"[^"]*"|[A-Za-z_][\w\.]*)
        (?:\s*,\s*(?P<second>"[^"]*"|[A-Za-z_][\w\.]*))?
    """,
    re.VERBOSE,
)


def go_rule_command_injection(path: Path, src: str, root: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    for m in _GO_EXEC_RX.finditer(src):
        prog = m.group("prog") or ""
        second = m.group("second") or ""
        rawshell = prog.strip('"') in ("sh", "/bin/sh", "bash", "/bin/bash", "zsh", "cmd", "cmd.exe")
        shell_flag = second.strip('"') in ("-c", "/C", "/c")
        dynamic_prog = not (prog.startswith('"') and prog.endswith('"'))
        if rawshell and shell_flag:
            findings.append(
                _go_cmdi(
                    path, src, root, m,
                    "exec.Command spawns a shell (sh -c / cmd /c) — any third argument is a shell command.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.LIKELY,
                )
            )
        elif dynamic_prog:
            findings.append(
                _go_cmdi(
                    path, src, root, m,
                    "exec.Command receives a non-literal program name — verify the input is "
                    "restricted against an allowlist before reaching here.",
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED,
                )
            )
    return findings


def _go_cmdi(path, src, root, m, desc, severity, confidence):
    return Finding(
        rule_id="GO-CMDI-001",
        title="Command execution sink in Go MCP handler",
        category=Category.COMMAND_INJECTION,
        severity=severity,
        confidence=confidence,
        description=desc,
        remediation=(
            "Prefer a fixed argv: exec.Command(\"tool\", \"--arg\", validatedInput). Never "
            "pass user input as the program name or to sh -c."
        ),
        evidence=[
            Evidence(
                location=f"{_rel(path, root)}:{_line(src, m.start())}",
                snippet=(src[m.start():m.start() + 180]).replace("\n", " ")[:240],
            )
        ],
        cwe=["CWE-78"],
        owasp_mcp="MCP05:2025",
        references=[
            "https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html",
        ],
    )


# ---------- SSRF ----------

_GO_HTTP_RX = re.compile(
    r"""\b(?:
        http\.Get
      | http\.Post
      | http\.PostForm
      | http\.Head
      | http\.DefaultClient\s*\.\s*(?:Get|Post|Do)
      | client\s*\.\s*(?:Get|Post|Do)
      | http\.NewRequest(?:WithContext)?
    )\s*\(""",
    re.VERBOSE,
)


def go_rule_ssrf(path: Path, src: str, root: Path) -> Iterable[Finding]:
    calls = list(_GO_HTTP_RX.finditer(src))
    if not calls:
        return []
    has_guard = bool(
        re.search(
            r"net\.ParseIP|net\.ResolveIPAddr|PrivateNetworks|net/netip\.ParseAddr|169\.254\.169\.254",
            src,
        )
    )
    out: list[Finding] = []
    for m in calls:
        out.append(
            Finding(
                rule_id="GO-SSRF-001",
                title="Outbound HTTP call — confirm host allowlist",
                category=Category.SSRF,
                severity=Severity.HIGH,
                confidence=Confidence.SUSPECTED if has_guard else Confidence.LIKELY,
                description=(
                    "HTTP call site found with no visible host-allowlist / private-IP check nearby. "
                    "Cloud IMDS (169.254.169.254), loopback, and RFC1918 are the typical SSRF targets."
                ),
                remediation=(
                    "Parse the URL, resolve the host, reject private / link-local / loopback. "
                    "Or use a preconfigured http.Client with a Dialer that filters addresses."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-918"],
                owasp_mcp="MCP07:2025",
            )
        )
    return out


# ---------- path traversal ----------

_GO_FILE_RX = re.compile(
    r"""\b(?:
        os\.Open | os\.OpenFile | os\.ReadFile | ioutil\.ReadFile
      | os\.Create | os\.WriteFile | ioutil\.WriteFile
    )\s*\(""",
    re.VERBOSE,
)


def go_rule_path(path: Path, src: str, root: Path) -> Iterable[Finding]:
    calls = list(_GO_FILE_RX.finditer(src))
    if not calls:
        return []
    has_guard = bool(
        re.search(
            r"filepath\.Clean|filepath\.Abs|filepath\.EvalSymlinks|strings\.HasPrefix",
            src,
        )
    )
    out: list[Finding] = []
    for m in calls:
        out.append(
            Finding(
                rule_id="GO-PATH-001",
                title="File API — confirm realpath-anchor guard",
                category=Category.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                confidence=Confidence.SUSPECTED if has_guard else Confidence.LIKELY,
                description=(
                    "File read/write sink with no visible filepath.EvalSymlinks + prefix check. "
                    "`..` / absolute paths / symlinks escape any intended root."
                ),
                remediation=(
                    "filepath.EvalSymlinks after joining with a root, then strings.HasPrefix "
                    "to confirm containment."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-22"],
            )
        )
    return out


# ---------- unsafe deserialization ----------

_GO_UNSAFE_DESER_RX = re.compile(
    r"""\b(?:
        yaml\.Unmarshal
      | gob\.NewDecoder\s*\(.*?\)\s*\.\s*Decode
      | gob\.Decode
      | xml\.Unmarshal
    )\s*\(""",
    re.VERBOSE | re.DOTALL,
)


def go_rule_unsafe_deser(path: Path, src: str, root: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _GO_UNSAFE_DESER_RX.finditer(src):
        out.append(
            Finding(
                rule_id="GO-DES-001",
                title="Potentially unsafe deserialization",
                category=Category.DESERIALIZATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.SUSPECTED,
                description=(
                    "Decoder/unmarshal on untrusted input — inspect the target struct for "
                    "`interface{}` slots or reflection paths that could enable exploitation."
                ),
                remediation="Strictly type the target struct; reject unexpected fields.",
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-502"],
            )
        )
    return out


# ---------- server bind / transport ----------

_GO_LISTEN_RX = re.compile(
    r"""\b(?:
        http\.ListenAndServe\s*\(
      | http\.ListenAndServeTLS\s*\(
      | net\.Listen\s*\(\s*"[a-z]+"\s*,\s*
    )""",
    re.VERBOSE,
)


def go_rule_bind_all_interfaces(path: Path, src: str, root: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _GO_LISTEN_RX.finditer(src):
        # Peek the first-arg address literal.
        after = src[m.end():m.end() + 120]
        addr = re.match(r"""\s*"([^"]+)"\s*""", after)
        if not addr:
            continue
        a = addr.group(1)
        bad = a.startswith(":") or a.startswith("0.0.0.0:") or a.startswith("[::]:")
        if not bad:
            continue
        out.append(
            Finding(
                rule_id="GO-AUTH-002",
                title=f"Server binds to all interfaces ({a})",
                category=Category.TRANSPORT,
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    "Bind address exposes the server on every interface. Pair with "
                    "missing auth and the server is internet-reachable."
                ),
                remediation='Bind to 127.0.0.1:PORT by default; require explicit opt-in for external exposure.',
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 120]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-668"],
                owasp_mcp="MCP02:2025",
            )
        )
    return out


# ---------- file driver ----------


def scan_go_file(path: Path, src: str, workdir: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(go_rule_command_injection(path, src, workdir))
    findings.extend(go_rule_ssrf(path, src, workdir))
    findings.extend(go_rule_path(path, src, workdir))
    findings.extend(go_rule_unsafe_deser(path, src, workdir))
    findings.extend(go_rule_bind_all_interfaces(path, src, workdir))
    return findings
