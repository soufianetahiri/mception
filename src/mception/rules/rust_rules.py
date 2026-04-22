"""Regex-based SAST rules for Rust MCP servers.

The Rust ecosystem is smaller and memory-safe by default, so we focus on
the pattern classes that actually cause CVEs in this layer:

- Shell-via-``Command`` (``Command::new("sh").arg("-c")`` or
  ``Command::new(dynamic)``).
- Unsafe deserialization (``bincode``, ``rmp_serde``, ``serde_json::from_slice``
  on untrusted bytes). Flag SUSPECTED only — these are library-level and
  exploitability depends on the ``Deserialize`` target.
- ``unsafe`` FFI into ``libc::system`` / ``libc::exec*``.
- Weak TLS (``danger_accept_invalid_certs(true)``, ditto hostnames).
- Path traversal via ``std::fs::File::open`` / ``create`` / ``write`` with a
  dynamic path and no ``canonicalize`` + prefix check.

Rust has no runtime ``eval``, so there is no ``RUST-CMDI-002`` equivalent.

Surface awareness: we check locally for ``wasm_bindgen::`` usage or
``cfg(target_arch = "wasm32")`` and demote in that case — Agent A owns
``surface.py`` extensions, so we don't touch it.
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


# ---------- local WASM-sandbox detection ----------

_WASM_SIGNAL_RX = re.compile(
    r"""wasm_bindgen\s*::|#\[\s*wasm_bindgen\s*[\]\(]|cfg\s*\(\s*target_arch\s*=\s*"wasm32"\s*\)""",
)


def _is_wasm_surface(src: str) -> bool:
    return bool(_WASM_SIGNAL_RX.search(src))


# ---------- binding detection ----------

# ``use std::process::Command`` / ``use std::process`` / ``use std::process::{Command, ...}``
_COMMAND_BINDING_RX = re.compile(
    r"""(?x)
    use\s+std\s*::\s*process\s*::\s*
        (?:Command|\{[^}]*\bCommand\b[^}]*\})
    | use\s+std\s*::\s*process\s*;
    """
)


# ---------- command injection ----------

# Match ``Command::new(...)`` — the arg can be a literal or identifier.
_COMMAND_NEW_RX = re.compile(
    r"""Command::new\s*\(\s*(?P<arg>"[^"]*"|[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)?|&[A-Za-z_]\w*)\s*\)""",
)
_SHELL_LITERALS = {"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "cmd", "cmd.exe"}
_SHELL_FLAG_RX = re.compile(r"""\.arg\s*\(\s*"(?:-c|/C|/c)"\s*\)""")
# Dynamic arg: ``.arg(format!(...))`` / ``.arg(&user)`` / ``.arg(user)``.
_DYNAMIC_ARG_RX = re.compile(
    r"""\.arg\s*\(\s*(?:format!|&?\s*[a-z_]\w*(?!\s*::))""",
)


def rust_rule_shell_command(path: Path, src: str, root: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    wasm = _is_wasm_surface(src)
    has_binding = bool(_COMMAND_BINDING_RX.search(src))
    for m in _COMMAND_NEW_RX.finditer(src):
        arg = m.group("arg")
        # Without an explicit ``use std::process...`` skip — avoids flagging a
        # user-defined ``Command`` type from some other crate.
        if not has_binding:
            continue
        is_literal = arg.startswith('"') and arg.endswith('"')
        program = arg.strip('"') if is_literal else None
        # Inspect file window after the call for ``.arg("-c")`` + dynamic arg.
        window = src[m.end():m.end() + 800]
        shell_flag_here = bool(_SHELL_FLAG_RX.search(window))
        dynamic_arg_here = bool(_DYNAMIC_ARG_RX.search(window))
        rawshell = is_literal and program in _SHELL_LITERALS
        if rawshell and shell_flag_here:
            # sh -c style.
            sev = Severity.MEDIUM if wasm else Severity.CRITICAL
            conf = Confidence.SUSPECTED if wasm else Confidence.LIKELY
            desc = (
                f"Command::new({program!r}) followed by .arg(\"-c\") is a shell invocation. "
                "Any subsequent argument assembled via format! or a bare identifier becomes a "
                "shell command."
            )
            findings.append(_make_cmdi(path, src, root, m, desc, sev, conf, wasm))
        elif not is_literal:
            # Dynamic program name, e.g. Command::new(user_input).
            sev = Severity.MEDIUM if wasm else Severity.HIGH
            conf = Confidence.SUSPECTED if wasm else Confidence.LIKELY
            desc = (
                "Command::new received a non-literal program name. Any caller-controlled input "
                "becomes the executable path."
            )
            findings.append(_make_cmdi(path, src, root, m, desc, sev, conf, wasm))
        elif dynamic_arg_here and rawshell:
            # Redundant with first branch but guards formatting.
            continue
    return findings


def _make_cmdi(path, src, root, m, desc, severity, confidence, wasm):
    note = " (wasm target — executes inside host sandbox, not the user OS)" if wasm else ""
    return Finding(
        rule_id="RUST-CMDI-001",
        title="Rust Command shell / dynamic program" + note,
        category=Category.COMMAND_INJECTION,
        severity=severity,
        confidence=confidence,
        description=desc,
        remediation=(
            "Use ``Command::new(\"executable\").args([\"--flag\", validated_arg])`` with a fixed "
            "executable and literal flags. Validate any dynamic segment against an allowlist."
        ),
        evidence=[
            Evidence(
                location=f"{_rel(path, root)}:{_line(src, m.start())}",
                snippet=(src[m.start():m.start() + 180]).replace("\n", " ")[:240],
            )
        ],
        cwe=["CWE-78"],
        owasp_mcp="MCP05:2025",
    )


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


# ---------- unsafe deserialization ----------

_DESER_RX = re.compile(
    r"""(?x)
    \b(?P<fn>
        bincode\s*::\s*deserialize(?:_from)?
      | rmp_serde\s*::\s*(?:from_slice|from_read|decode::from_slice)
      | serde_json\s*::\s*from_slice
      | serde_json\s*::\s*from_reader
      | serde_yaml\s*::\s*from_str
      | serde_yaml\s*::\s*from_slice
    )\s*\(
    """
)


def rust_rule_unsafe_deser(path: Path, src: str, root: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _DESER_RX.finditer(src):
        fn = m.group("fn").strip()
        out.append(
            Finding(
                rule_id="RUST-DES-001",
                title=f"Deserialization sink: {fn}",
                category=Category.DESERIALIZATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.SUSPECTED,
                description=(
                    f"{fn} on untrusted bytes can drive panics or, depending on the "
                    "``Deserialize`` target, resource-exhaustion. Safer than Python pickle or "
                    "Ruby Marshal, but not harmless."
                ),
                remediation=(
                    "Strictly type the target struct, reject unexpected fields "
                    "(``#[serde(deny_unknown_fields)]``), and bound the input size."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:220],
                    )
                ],
                cwe=["CWE-502"],
            )
        )
    return out


# ---------- unsafe FFI ----------

_UNSAFE_BLOCK_RX = re.compile(r"unsafe\s*\{", re.DOTALL)
_LIBC_SYSTEM_RX = re.compile(r"""libc\s*::\s*(?:system|exec[lv]e?p?|popen)\s*\(""")


def rust_rule_unsafe_ffi(path: Path, src: str, root: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    # Find unsafe {...} blocks and flag libc::system / exec inside them.
    for m in _LIBC_SYSTEM_RX.finditer(src):
        # Look backwards up to 400 chars for an unsafe block opener.
        window_start = max(0, m.start() - 400)
        before = src[window_start:m.start()]
        if "unsafe" not in before:
            continue
        out.append(
            Finding(
                rule_id="RUST-FFI-001",
                title="Unsafe FFI to libc process API",
                category=Category.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                confidence=Confidence.LIKELY,
                description=(
                    "``libc::system`` / ``libc::exec*`` invoked from an ``unsafe`` block bypasses "
                    "all of Rust's safe Command APIs and reintroduces classic C shell-injection "
                    "footguns."
                ),
                remediation=(
                    "Replace with ``std::process::Command`` using explicit argv; there is almost "
                    "never a reason to drop to libc for process spawning."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:220],
                    )
                ],
                cwe=["CWE-78", "CWE-242"],
                owasp_mcp="MCP05:2025",
            )
        )
    return out


# ---------- weak TLS ----------

_TLS_OFF_RX = re.compile(
    r"""danger_accept_invalid_certs\s*\(\s*true\s*\)|danger_accept_invalid_hostnames\s*\(\s*true\s*\)""",
)


def rust_rule_weak_tls(path: Path, src: str, root: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _TLS_OFF_RX.finditer(src):
        out.append(
            Finding(
                rule_id="RUST-AUTH-001",
                title="TLS verification disabled",
                category=Category.TRANSPORT,
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    "``danger_accept_invalid_certs(true)`` / ``danger_accept_invalid_hostnames(true)`` "
                    "disables TLS validation. Any MITM on the wire can read / tamper with traffic."
                ),
                remediation="Remove. Configure a proper root-cert bundle via rustls-native-certs or similar.",
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:220],
                    )
                ],
                cwe=["CWE-295"],
            )
        )
    return out


# ---------- path traversal ----------

_FS_FILE_RX = re.compile(
    r"""(?x)
    \b(?:std\s*::\s*)?fs\s*::\s*(?:read_to_string|read|write|File\s*::\s*(?:open|create|write))
    \s*\(\s*
    (?P<arg>&?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?|"[^"]*"|format!\s*\()
    """,
)
_PATH_GUARD_RX = re.compile(
    r"""canonicalize|starts_with|strip_prefix|PathBuf::from\s*\([^)]*canonicalize""",
)


def rust_rule_path_traversal(path: Path, src: str, root: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    has_guard = bool(_PATH_GUARD_RX.search(src))
    for m in _FS_FILE_RX.finditer(src):
        arg = m.group("arg")
        is_literal = arg.startswith('"') and arg.endswith('"')
        if is_literal:
            continue
        out.append(
            Finding(
                rule_id="RUST-PATH-001",
                title="std::fs path sink with dynamic argument",
                category=Category.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                confidence=Confidence.SUSPECTED if has_guard else Confidence.LIKELY,
                description=(
                    "File read/write sink with a dynamic path and no visible ``canonicalize`` "
                    "+ ``starts_with`` guard. ``..`` / absolute paths / symlinks escape any "
                    "intended root."
                ),
                remediation=(
                    "Canonicalize the path (``Path::canonicalize``), then assert the result "
                    "``starts_with`` your fixed root."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, root)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:220],
                    )
                ],
                cwe=["CWE-22"],
                owasp_mcp="MCP06:2025",
            )
        )
    return out


# ---------- file driver ----------


def scan_rust_file(path: Path, src: str, workdir: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(rust_rule_shell_command(path, src, workdir))
    findings.extend(rust_rule_ssrf(path, src, workdir))
    findings.extend(rust_rule_unsafe_deser(path, src, workdir))
    findings.extend(rust_rule_unsafe_ffi(path, src, workdir))
    findings.extend(rust_rule_weak_tls(path, src, workdir))
    findings.extend(rust_rule_path_traversal(path, src, workdir))
    return findings
