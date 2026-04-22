"""Regex-based SAST rules for Ruby MCP servers.

Ruby has a few shapes that dominate real-world exploits: backticks /
``%x{}`` / ``system`` / ``exec`` / ``IO.popen`` as shell entry points,
``eval`` and its friends as raw code-exec, ``Marshal.load`` / ``YAML.load``
as deserialization, ``open-uri``-hijacked ``Kernel#open`` as SSRF, and
``File.read/write/open`` as path-traversal candidates.

These rules mirror the calibration approach used in ``node_rules.py``:
import-binding awareness (e.g. has the file ``require``'d ``open-uri``?),
``(?<![.\\w])`` lookbehind to avoid flagging ``foo.system(...)`` on a custom
receiver, and severity/confidence escalation when the first argument is
interpolated / concatenated / a bare identifier.

Surface awareness: when ``classify_surface`` returns ``"sandbox"`` or
``"build"``, severities are demoted in the same way ``node_rule_eval`` does.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity
from .surface import classify_surface

RUBY_EXTS = (".rb", ".rake", ".gemspec")
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    "vendor",
    "tmp",
    "log",
    "coverage",
    ".bundle",
    ".venv",
    "venv",
}


# ---------- helpers ----------


def _ruby_sources(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if any(part in ("test", "tests", "spec") for part in p.parts):
            continue
        if p.suffix.lower() in RUBY_EXTS:
            yield p


def _line(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


# ---------- dynamism detector ----------

# Ruby dynamic-first-arg heuristic. Matches:
#   "hello #{x}"              -> string interpolation
#   "hello " + x              -> string concat
#   some_var                  -> bare identifier
#   "prefix" << x             -> shovel concat
_DYNAMIC_ARG_RX = re.compile(
    r"""
    ["'][^"']*\#\{          # "...#{var}..."
    | ["'][^"']*["']\s*\+   # "..." +
    | \+\s*[a-z_]\w*        # + var
    | <<\s*[a-z_]\w*        # << var
    """,
    re.VERBOSE,
)


def _is_dynamic(arg: str) -> bool:
    arg = arg.strip()
    if not arg:
        return False
    if _DYNAMIC_ARG_RX.search(arg):
        return True
    # Bare identifier call like `system(cmd)` -> cmd is a variable.
    if re.match(r"^[a-z_]\w*\s*$", arg):
        return True
    return False


def _first_call_arg(src: str, start: int) -> str | None:
    """Walk balanced parens from *start* (just past an opening ``(``) and return
    the first top-level argument up to ``,`` or the matching ``)``."""
    depth = 1
    in_single = in_double = False
    escape = False
    i = start
    arg_start = start
    while i < len(src):
        ch = src[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\":
            escape = True
            i += 1
            continue
        if not in_double and ch == "'":
            in_single = not in_single
        elif not in_single and ch == '"':
            in_double = not in_double
        elif not (in_single or in_double):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    return src[arg_start:i]
            elif ch == "," and depth == 1:
                return src[arg_start:i]
        i += 1
    return None


# ---------- surface calibration ----------


def _surface_demote(
    surface: str, crit: Severity = Severity.CRITICAL
) -> tuple[Severity, Confidence, str]:
    """Return ``(severity, confidence, note)`` adjusted for the execution
    surface. Mirrors ``node_rule_eval`` treatment."""
    if surface == "sandbox":
        return (
            Severity.MEDIUM,
            Confidence.SUSPECTED,
            " (sandbox surface — evaluated inside host-managed runtime)",
        )
    if surface == "build":
        return (
            Severity.LOW,
            Confidence.SUSPECTED,
            " (build-time config — runs only during build/test)",
        )
    return crit, Confidence.LIKELY, ""


# ---------- rule: command injection / shell sinks ----------

# Kernel-level shell sinks. The ``(?<![.\w])`` lookbehind prevents matches
# like ``obj.system(...)`` (a custom method on a receiver) or ``foo_exec(...)``.
_SHELL_CALL_RX = re.compile(
    r"""(?x)
    (?<![.\w])
    (?P<fn>
        system
      | exec
      | spawn
      | Process\.spawn
      | IO\.popen
      | Open3\.(?:capture2|capture2e|capture3|popen2|popen2e|popen3)
      | Kernel\.(?:system|exec|spawn)
    )
    \s*\(
    """
)
# Backtick and %x{} / %x[] / %x() / %x!! forms always shell-exec.
_BACKTICK_RX = re.compile(r"`[^`\n]*#\{[^`]*`|`[^`\n]*\+[^`\n]*`")
_PCT_X_RX = re.compile(r"%x[{\[\(!](?P<body>[^}\]\)!]*)[}\]\)!]")


def ruby_rule_command_injection(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    findings: list[Finding] = []
    surface = classify_surface(path, src, workdir)
    # Function-style shell sinks.
    for m in _SHELL_CALL_RX.finditer(src):
        fn = m.group("fn")
        arg = _first_call_arg(src, m.end()) or ""
        dynamic = _is_dynamic(arg)
        sev, conf, surface_note = _surface_demote(surface)
        if not dynamic:
            # Literal argv like ``system("ls", "-la")`` -> still worth surfacing
            # but not critical.
            sev = Severity.HIGH if surface not in ("sandbox", "build") else sev
            conf = Confidence.SUSPECTED
        findings.append(
            Finding(
                rule_id="RUBY-CMDI-001",
                title=f"Shell sink: {fn}(){surface_note}",
                category=Category.COMMAND_INJECTION,
                severity=sev,
                confidence=conf,
                description=(
                    f"{fn} invokes a shell (or a process via the kernel). With an interpolated or "
                    "concatenated argument, any user-controlled fragment becomes a shell command."
                ),
                remediation=(
                    "Use the multi-argument form (``system(cmd, arg1, arg2)``) or ``Open3.capture3`` "
                    "with an explicit argv array so the shell is bypassed. Validate any dynamic "
                    "segment against an allowlist."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-78"],
                owasp_mcp="MCP05:2025",
                references=[
                    "https://owasp.org/www-community/attacks/Command_Injection",
                ],
            )
        )
    # Backticks with interpolation/concat.
    for m in _BACKTICK_RX.finditer(src):
        sev, conf, surface_note = _surface_demote(surface)
        findings.append(
            Finding(
                rule_id="RUBY-CMDI-001",
                title=f"Backtick shell exec with dynamic content{surface_note}",
                category=Category.COMMAND_INJECTION,
                severity=sev,
                confidence=conf,
                description=(
                    "Ruby backticks invoke ``/bin/sh -c`` with the string body. Interpolated "
                    "segments become unescaped shell fragments."
                ),
                remediation="Replace with Open3.capture3 and an explicit argv array.",
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-78"],
                owasp_mcp="MCP05:2025",
            )
        )
    # %x{...} forms.
    for m in _PCT_X_RX.finditer(src):
        body = m.group("body")
        if "#{" not in body and "+" not in body:
            continue
        sev, conf, surface_note = _surface_demote(surface)
        findings.append(
            Finding(
                rule_id="RUBY-CMDI-001",
                title=f"%x{{}} shell exec with dynamic content{surface_note}",
                category=Category.COMMAND_INJECTION,
                severity=sev,
                confidence=conf,
                description="``%x{...}`` is equivalent to backticks: shell invocation of the body.",
                remediation="Replace with Open3.capture3 and an explicit argv array.",
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-78"],
                owasp_mcp="MCP05:2025",
            )
        )
    return findings


# ---------- rule: eval / instance_eval / class_eval / ERB ----------

_EVAL_RX = re.compile(
    r"""(?x)
    (?<![.\w])
    (?P<fn>
        eval
      | instance_eval
      | class_eval
      | module_eval
      | Kernel\.eval
    )
    \s*\(
    """
)
_ERB_RX = re.compile(r"""ERB\.new\s*\(""")


def ruby_rule_eval(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    surface = classify_surface(path, src, workdir)
    sev, conf, surface_note = _surface_demote(surface)
    for m in _EVAL_RX.finditer(src):
        fn = m.group("fn")
        arg = _first_call_arg(src, m.end()) or ""
        dynamic = _is_dynamic(arg)
        this_sev = sev if dynamic else Severity.HIGH
        this_conf = conf if dynamic else Confidence.SUSPECTED
        if surface in ("sandbox", "build"):
            # Keep demoted severity regardless.
            this_sev, this_conf = sev, conf
        out.append(
            Finding(
                rule_id="RUBY-CMDI-002",
                title=f"Dynamic code execution via {fn}(){surface_note}",
                category=Category.COMMAND_INJECTION,
                severity=this_sev,
                confidence=this_conf,
                description=(
                    f"{fn} runs arbitrary Ruby source. Any user-controlled fragment grants "
                    "full code-exec authority."
                ),
                remediation=(
                    "Remove. If templating is needed use a safe templating library. If dynamic "
                    "dispatch is needed, use ``public_send`` with a whitelist."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-95"],
                owasp_mcp="MCP05:2025",
            )
        )
    for m in _ERB_RX.finditer(src):
        arg = _first_call_arg(src, m.end()) or ""
        if not _is_dynamic(arg):
            continue
        out.append(
            Finding(
                rule_id="RUBY-CMDI-002",
                title=f"ERB.new with dynamic template{surface_note}",
                category=Category.COMMAND_INJECTION,
                severity=sev,
                confidence=conf,
                description=(
                    "ERB templates compile to Ruby; a dynamic template string reduces to ``eval``."
                ),
                remediation="Load templates from a fixed on-disk file; do not interpolate input.",
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-95"],
                owasp_mcp="MCP05:2025",
            )
        )
    return out


# ---------- rule: unsafe deserialization ----------

_DESER_RX = re.compile(
    r"""(?x)
    (?<![.\w])
    (?P<fn>
        Marshal\.load
      | Marshal\.restore
      | YAML\.load            # unsafe default pre-Psych 4 / Ruby 3.1
      | YAML\.unsafe_load
      | Psych\.load
      | Psych\.unsafe_load
    )
    \s*\(
    """
)


def ruby_rule_deserialization(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _DESER_RX.finditer(src):
        fn = m.group("fn")
        # Marshal.load on untrusted input is straight RCE.
        marshal = fn.startswith("Marshal")
        unsafe_yaml = fn in ("YAML.unsafe_load", "Psych.unsafe_load")
        if marshal or unsafe_yaml:
            sev = Severity.CRITICAL
            conf = Confidence.LIKELY
        else:
            # YAML.load is context-dependent (Psych 4 made it safe by default).
            sev = Severity.HIGH
            conf = Confidence.SUSPECTED
        out.append(
            Finding(
                rule_id="RUBY-DES-001",
                title=f"Unsafe deserialization via {fn}",
                category=Category.DESERIALIZATION,
                severity=sev,
                confidence=conf,
                description=(
                    f"{fn} can instantiate arbitrary Ruby classes from serialized bytes. With "
                    "untrusted input this is remote code execution (Marshal) or class-ladder "
                    "exploitation (YAML)."
                ),
                remediation=(
                    "Never ``Marshal.load`` untrusted data. For YAML use ``YAML.safe_load`` (or "
                    "``Psych.safe_load``) with a strict ``permitted_classes`` list."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 140]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-502"],
                owasp_mcp="MCP05:2025",
            )
        )
    return out


# ---------- rule: SSRF ----------

# ``open`` is hijacked by ``open-uri``, so we only flag bare ``open(...)`` when
# ``require 'open-uri'`` / ``require "open-uri"`` is present.
_OPEN_URI_RX = re.compile(r"""require\s*\(?\s*["']open-uri["']""")
_NET_HTTP_RX = re.compile(
    r"""(?x)
    (?<![.\w])
    (?P<fn>
        Net::HTTP\.get(?:_response)?
      | Net::HTTP\.post(?:_form)?
      | Net::HTTP\.start
      | URI\.open
      | HTTParty\.(?:get|post|put|delete)
      | Faraday\.(?:get|post|put|delete|new)
    )
    \s*\(
    """
)
_BARE_OPEN_RX = re.compile(r"""(?<![.\w])open\s*\(""")
_SSRF_GUARD_RX = re.compile(
    r"""IPAddr|private_ip|allowlist|allow_list|169\.254\.169\.254|127\.0\.0\.1|loopback""",
    re.IGNORECASE,
)


def ruby_rule_ssrf(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    has_guard = bool(_SSRF_GUARD_RX.search(src))
    has_open_uri = bool(_OPEN_URI_RX.search(src))
    calls: list[tuple[re.Match[str], str]] = []
    for m in _NET_HTTP_RX.finditer(src):
        calls.append((m, m.group("fn")))
    if has_open_uri:
        for m in _BARE_OPEN_RX.finditer(src):
            calls.append((m, "open (open-uri)"))
    for m, fn in calls:
        arg = _first_call_arg(src, m.end()) or ""
        if not _is_dynamic(arg):
            continue
        out.append(
            Finding(
                rule_id="RUBY-SSRF-001",
                title=f"Outbound HTTP via {fn} with dynamic URL",
                category=Category.SSRF,
                severity=Severity.HIGH,
                confidence=Confidence.SUSPECTED if has_guard else Confidence.LIKELY,
                description=(
                    "Dynamic URL passed to an HTTP client with no obvious allowlist / private-IP "
                    "block in the file. Attackers can pivot to cloud IMDS, localhost, or "
                    "file:// / ftp:// schemes (open-uri still honours these)."
                ),
                remediation=(
                    "Parse via ``URI.parse``, assert ``scheme == 'https'``, resolve the host and "
                    "reject loopback / link-local / RFC1918 / 169.254.169.254."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-918"],
                owasp_mcp="MCP07:2025",
            )
        )
    return out


# ---------- rule: path traversal ----------

_FILE_IO_RX = re.compile(
    r"""(?x)
    (?<![.\w])
    (?P<fn>
        File\.read
      | File\.write
      | File\.open
      | File\.binread
      | File\.binwrite
      | IO\.read
      | IO\.write
      | Pathname\.new
    )
    \s*\(
    """
)
_PATH_GUARD_RX = re.compile(
    r"""File\.expand_path|Pathname\.new.*realpath|realpath|start_with\?|include\?\s*\(\s*['"]\.\.['"]\s*\)""",
    re.IGNORECASE,
)


def ruby_rule_path_traversal(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    has_guard = bool(_PATH_GUARD_RX.search(src))
    for m in _FILE_IO_RX.finditer(src):
        fn = m.group("fn")
        arg = _first_call_arg(src, m.end()) or ""
        if not _is_dynamic(arg):
            continue
        out.append(
            Finding(
                rule_id="RUBY-PATH-001",
                title=f"Path traversal risk in {fn}",
                category=Category.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                confidence=Confidence.SUSPECTED if has_guard else Confidence.LIKELY,
                description=(
                    f"{fn} receives a dynamic path with no visible realpath-anchor check. "
                    "``..`` / absolute paths / symlinks escape any intended root."
                ),
                remediation=(
                    "Join against a fixed root via ``File.expand_path``, call ``.realpath``, then "
                    "assert the result ``start_with?`` the root. Reject absolute paths outright."
                ),
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 160]).replace("\n", " ")[:240],
                    )
                ],
                cwe=["CWE-22"],
                owasp_mcp="MCP06:2025",
            )
        )
    return out


# ---------- rule: weak TLS ----------

_TLS_OFF_RX = re.compile(
    r"""OpenSSL::SSL::VERIFY_NONE|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE""",
)


def ruby_rule_weak_tls(path: Path, src: str, workdir: Path) -> Iterable[Finding]:
    out: list[Finding] = []
    for m in _TLS_OFF_RX.finditer(src):
        out.append(
            Finding(
                rule_id="RUBY-AUTH-001",
                title="TLS verification disabled (VERIFY_NONE)",
                category=Category.TRANSPORT,
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    "``OpenSSL::SSL::VERIFY_NONE`` disables TLS certificate validation. Any MITM "
                    "on the wire can read / tamper with traffic."
                ),
                remediation="Remove. Use VERIFY_PEER (the default) and provide a proper CA bundle.",
                evidence=[
                    Evidence(
                        location=f"{_rel(path, workdir)}:{_line(src, m.start())}",
                        snippet=(src[m.start():m.start() + 120]).replace("\n", " ")[:200],
                    )
                ],
                cwe=["CWE-295"],
            )
        )
    return out


# ---------- file driver ----------


def scan_ruby_file(path: Path, src: str, workdir: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(ruby_rule_command_injection(path, src, workdir))
    findings.extend(ruby_rule_eval(path, src, workdir))
    findings.extend(ruby_rule_deserialization(path, src, workdir))
    findings.extend(ruby_rule_ssrf(path, src, workdir))
    findings.extend(ruby_rule_path_traversal(path, src, workdir))
    findings.extend(ruby_rule_weak_tls(path, src, workdir))
    return findings
