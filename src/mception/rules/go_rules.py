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
from .surface import classify_surface

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


# ---------- import-binding tracker ----------

# Each Go import in a file is one of:
#   import "os/exec"
#   import exc "os/exec"
#   import _ "os/exec"            (side-effect; the name isn't usable — skip)
#   import . "os/exec"            (dot-import: names inlined into this package)
#   import (
#       "os/exec"
#       exc "os/exec"
#   )
# We parse both the single-line and parenthesised block forms with regex, no AST.
_IMPORT_SINGLE_RX = re.compile(
    r'^\s*import\s+(?:(?P<alias>[A-Za-z_\.][\w]*)\s+)?"(?P<path>[^"]+)"',
    re.MULTILINE,
)
_IMPORT_BLOCK_RX = re.compile(r"^\s*import\s*\(\s*(?P<body>.*?)\s*\)", re.MULTILINE | re.DOTALL)
_IMPORT_BLOCK_LINE_RX = re.compile(
    r'^\s*(?:(?P<alias>[A-Za-z_\.][\w]*)\s+)?"(?P<path>[^"]+)"\s*$',
    re.MULTILINE,
)

# Default package name derived from an import path = the last path segment.
# For the stdlib paths we care about: os/exec → "exec", encoding/gob → "gob",
# io/ioutil → "ioutil", net/http → "http", plugin → "plugin", os → "os".


def _default_pkg_name(import_path: str) -> str:
    return import_path.rsplit("/", 1)[-1]


def _import_bindings(src: str) -> dict[str, set[str]]:
    """Return {import_path: {name_used_in_source, ...}}.

    - Unaliased imports bind the default package name.
    - Aliased imports bind that alias (and only that alias).
    - `_` side-effect imports bind nothing.
    - `.` dot-imports are flagged with the special name "." so rules can decide
      to fall back to bare-name matching if they really want to.
    """
    bindings: dict[str, set[str]] = {}

    def _record(alias: str | None, path: str) -> None:
        if alias == "_":
            return  # side-effect import, no usable name
        name = alias if alias else _default_pkg_name(path)
        bindings.setdefault(path, set()).add(name)

    # Single-line imports.
    for m in _IMPORT_SINGLE_RX.finditer(src):
        _record(m.group("alias"), m.group("path"))

    # Block imports: pull out each body, then iterate lines.
    for blk in _IMPORT_BLOCK_RX.finditer(src):
        for ln in _IMPORT_BLOCK_LINE_RX.finditer(blk.group("body")):
            _record(ln.group("alias"), ln.group("path"))

    return bindings


def _names_for(bindings: dict[str, set[str]], import_path: str) -> set[str]:
    """Return usable names for *import_path*, empty set if not imported."""
    return bindings.get(import_path, set())


# ---------- command injection ----------

# exec.Command("sh", "-c", ...)  /  exec.Command(userInput, ...)
# The `(?<![.\w])` lookbehind blocks `foo.exec.Command` / `myexec.Command`.
# The <pkg> group is filled in dynamically based on the file's import bindings.
def _exec_rx_for(names: set[str]) -> re.Pattern[str] | None:
    if not names:
        return None
    pkg = "|".join(re.escape(n) for n in names)
    return re.compile(
        rf"""(?<![.\w])(?:{pkg})\s*\.\s*Command(?:Context)?\s*\(\s*
            (?P<prog>"[^"]*"|[A-Za-z_][\w\.]*)
            (?:\s*,\s*(?P<second>"[^"]*"|[A-Za-z_][\w\.]*))?
        """,
        re.VERBOSE,
    )


def go_rule_command_injection(
    path: Path, src: str, root: Path, bindings: dict[str, set[str]], surface: str
) -> Iterable[Finding]:
    # WASM / JS sandbox target has no syscall surface — exec sinks are dead code.
    if surface == "sandbox":
        return []
    names = _names_for(bindings, "os/exec")
    rx = _exec_rx_for(names)
    if rx is None:
        return []
    findings: list[Finding] = []
    for m in rx.finditer(src):
        prog = m.group("prog") or ""
        second = m.group("second") or ""
        rawshell = prog.strip('"') in ("sh", "/bin/sh", "bash", "/bin/bash", "zsh", "cmd", "cmd.exe")
        shell_flag = second.strip('"') in ("-c", "/C", "/c")
        dynamic_prog = not (prog.startswith('"') and prog.endswith('"'))
        if rawshell and shell_flag:
            sev, conf = Severity.CRITICAL, Confidence.LIKELY
            desc = "exec.Command spawns a shell (sh -c / cmd /c) — any third argument is a shell command."
        elif dynamic_prog:
            sev, conf = Severity.HIGH, Confidence.SUSPECTED
            desc = (
                "exec.Command receives a non-literal program name — verify the input is "
                "restricted against an allowlist before reaching here."
            )
        else:
            continue
        if surface == "build":
            sev = _demote(sev)
        findings.append(_go_cmdi(path, src, root, m, desc, severity=sev, confidence=conf))
    return findings


def _demote(sev: Severity) -> Severity:
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    try:
        i = order.index(sev)
        return order[min(i + 1, len(order) - 1)]
    except ValueError:
        return sev


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


# ---------- plugin.Open ----------


def go_rule_plugin_open(
    path: Path, src: str, root: Path, bindings: dict[str, set[str]], surface: str
) -> Iterable[Finding]:
    names = _names_for(bindings, "plugin")
    if not names:
        return []
    pkg = "|".join(re.escape(n) for n in names)
    rx = re.compile(rf"(?<![.\w])(?:{pkg})\s*\.\s*Open\s*\(")
    out: list[Finding] = []
    # plugin.Open is unavailable on wasm — demote if sandbox.
    base_sev = Severity.HIGH
    if surface == "sandbox":
        base_sev = Severity.MEDIUM
    elif surface == "build":
        base_sev = _demote(base_sev)
    for m in rx.finditer(src):
        out.append(
            Finding(
                rule_id="GO-PLUG-001",
                title="plugin.Open loads shared-object at runtime",
                category=Category.SANDBOX_ESCAPE,
                severity=base_sev,
                confidence=Confidence.LIKELY,
                description=(
                    "plugin.Open loads an arbitrary .so file. If the path is attacker-"
                    "controlled, this is RCE via native code load."
                ),
                remediation=(
                    "Restrict plugin paths to a fixed allowlist shipped with the binary, "
                    "or eliminate the plugin system entirely."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-94"],
            )
        )
    return out


# ---------- SSRF ----------

_GO_HTTP_NAMESPACED = (
    # pattern -> (import_path_required, is_method_on_stdlib_value)
    # For each, we build the regex dynamically with the file's bindings.
)


def _http_rx_for(names: set[str]) -> re.Pattern[str] | None:
    if not names:
        return None
    pkg = "|".join(re.escape(n) for n in names)
    return re.compile(
        rf"""(?<![.\w])(?:
            (?:{pkg})\.Get
          | (?:{pkg})\.Post
          | (?:{pkg})\.PostForm
          | (?:{pkg})\.Head
          | (?:{pkg})\.DefaultClient\s*\.\s*(?:Get|Post|Do)
          | (?:{pkg})\.NewRequest(?:WithContext)?
        )\s*\(""",
        re.VERBOSE,
    )


# `client.Get|Post|Do` — idiomatic http.Client receiver. Not package-qualified;
# we allow it whenever net/http is imported (it implies a Client is in scope).
_GO_CLIENT_METHOD_RX = re.compile(
    r"(?<![.\w])client\s*\.\s*(?:Get|Post|Do)\s*\(",
)


def go_rule_ssrf(
    path: Path, src: str, root: Path, bindings: dict[str, set[str]], surface: str
) -> Iterable[Finding]:
    names = _names_for(bindings, "net/http")
    if not names:
        return []
    rx = _http_rx_for(names)
    calls = list(rx.finditer(src)) if rx else []
    calls += list(_GO_CLIENT_METHOD_RX.finditer(src))
    if not calls:
        return []
    has_guard = bool(
        re.search(
            r"net\.ParseIP|net\.ResolveIPAddr|PrivateNetworks|net/netip\.ParseAddr|169\.254\.169\.254",
            src,
        )
    )
    sev = Severity.HIGH
    if surface == "build":
        sev = _demote(sev)
    out: list[Finding] = []
    for m in calls:
        out.append(
            Finding(
                rule_id="GO-SSRF-001",
                title="Outbound HTTP call — confirm host allowlist",
                category=Category.SSRF,
                severity=sev,
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


def _file_rx_for(os_names: set[str], ioutil_names: set[str]) -> re.Pattern[str] | None:
    parts: list[str] = []
    if os_names:
        pkg = "|".join(re.escape(n) for n in os_names)
        parts.append(
            rf"(?:{pkg})\.(?:Open|OpenFile|ReadFile|Create|WriteFile)"
        )
    if ioutil_names:
        pkg = "|".join(re.escape(n) for n in ioutil_names)
        parts.append(rf"(?:{pkg})\.(?:ReadFile|WriteFile)")
    if not parts:
        return None
    body = "|".join(parts)
    return re.compile(rf"(?<![.\w])(?:{body})\s*\(", re.VERBOSE)


def go_rule_path(
    path: Path, src: str, root: Path, bindings: dict[str, set[str]], surface: str
) -> Iterable[Finding]:
    os_names = _names_for(bindings, "os")
    ioutil_names = _names_for(bindings, "io/ioutil")
    rx = _file_rx_for(os_names, ioutil_names)
    if rx is None:
        return []
    calls = list(rx.finditer(src))
    if not calls:
        return []
    has_guard = bool(
        re.search(
            r"filepath\.Clean|filepath\.Abs|filepath\.EvalSymlinks|strings\.HasPrefix",
            src,
        )
    )
    sev = Severity.HIGH
    if surface == "build":
        sev = _demote(sev)
    out: list[Finding] = []
    for m in calls:
        out.append(
            Finding(
                rule_id="GO-PATH-001",
                title="File API — confirm realpath-anchor guard",
                category=Category.PATH_TRAVERSAL,
                severity=sev,
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


def _deser_rx_for(gob_names: set[str]) -> re.Pattern[str] | None:
    # yaml and xml are third-party / stdlib without a dedicated binding check
    # here — we still need *some* matcher so existing tests keep working. Emit
    # a pattern that optionally includes gob when imported.
    parts = [r"yaml\.Unmarshal", r"xml\.Unmarshal"]
    if gob_names:
        pkg = "|".join(re.escape(n) for n in gob_names)
        parts.append(rf"(?:{pkg})\.NewDecoder\s*\(.*?\)\s*\.\s*Decode")
        parts.append(rf"(?:{pkg})\.Decode")
    body = "|".join(parts)
    return re.compile(rf"(?<![.\w])(?:{body})\s*\(", re.VERBOSE | re.DOTALL)


def go_rule_unsafe_deser(
    path: Path, src: str, root: Path, bindings: dict[str, set[str]], surface: str
) -> Iterable[Finding]:
    gob_names = _names_for(bindings, "encoding/gob")
    rx = _deser_rx_for(gob_names)
    if rx is None:
        return []
    sev = Severity.MEDIUM
    if surface == "build":
        sev = _demote(sev)
    out: list[Finding] = []
    for m in rx.finditer(src):
        out.append(
            Finding(
                rule_id="GO-DES-001",
                title="Potentially unsafe deserialization",
                category=Category.DESERIALIZATION,
                severity=sev,
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


def _listen_rx_for(names: set[str]) -> re.Pattern[str] | None:
    if not names:
        return None
    pkg = "|".join(re.escape(n) for n in names)
    return re.compile(
        rf"""(?<![.\w])(?:
            (?:{pkg})\.ListenAndServe\s*\(
          | (?:{pkg})\.ListenAndServeTLS\s*\(
        )""",
        re.VERBOSE,
    )


def go_rule_bind_all_interfaces(
    path: Path, src: str, root: Path, bindings: dict[str, set[str]], surface: str
) -> Iterable[Finding]:
    http_names = _names_for(bindings, "net/http")
    rx = _listen_rx_for(http_names)
    out: list[Finding] = []
    matches = list(rx.finditer(src)) if rx else []
    # `net.Listen("tcp", ...)` — depends on net import.
    net_names = _names_for(bindings, "net")
    if net_names:
        net_pkg = "|".join(re.escape(n) for n in net_names)
        net_rx = re.compile(
            rf'(?<![.\w])(?:{net_pkg})\.Listen\s*\(\s*"[a-z]+"\s*,\s*',
        )
        matches.extend(net_rx.finditer(src))
    sev = Severity.HIGH
    if surface == "build":
        sev = _demote(sev)
    for m in matches:
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
                severity=sev,
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
    bindings = _import_bindings(src)
    surface = classify_surface(path, src, workdir)
    findings: list[Finding] = []
    findings.extend(go_rule_command_injection(path, src, workdir, bindings, surface))
    findings.extend(go_rule_plugin_open(path, src, workdir, bindings, surface))
    findings.extend(go_rule_ssrf(path, src, workdir, bindings, surface))
    findings.extend(go_rule_path(path, src, workdir, bindings, surface))
    findings.extend(go_rule_unsafe_deser(path, src, workdir, bindings, surface))
    findings.extend(go_rule_bind_all_interfaces(path, src, workdir, bindings, surface))
    return findings
