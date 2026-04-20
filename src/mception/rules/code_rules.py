"""AST-based source rules for tool handler code.

Strategy (deliberately simple, not full taint):
  - Find MCP tool-handler functions (decorated with @mcp.tool / @mcp.resource / @mcp.prompt).
  - Collect their parameter names.
  - Walk the function body. For each call whose callee matches a dangerous sink,
    look at arguments. If any argument is an `ast.Name` referring to a parameter,
    or an `ast.BinOp`/`ast.JoinedStr`/`ast.Call(format)` that mentions a parameter,
    emit a Finding with Confidence=Likely. Otherwise Confidence=Suspected.
  - Unconditionally dangerous sinks (eval, pickle.loads, yaml.load without SafeLoader,
    subprocess with shell=True and a non-literal command) are Confirmed in that they
    *are* in the code — severity set by category.

Scope: Python only. Covers Python-implemented MCP servers (a very common case).
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity


@dataclass
class CodeContext:
    workdir: Path
    source_file: Path
    func_node: ast.FunctionDef | ast.AsyncFunctionDef
    param_names: set[str]

    def loc(self, node: ast.AST) -> str:
        rel = _safe_relpath(self.source_file, self.workdir)
        return f"{rel}:{getattr(node, 'lineno', self.func_node.lineno)}"

    def snippet(self, node: ast.AST) -> str | None:
        try:
            return ast.unparse(node)[:240]
        except Exception:
            return None


def _safe_relpath(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def iter_tool_handlers(tree: ast.AST) -> Iterable[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                target = d.func if isinstance(d, ast.Call) else d
                attr = None
                if isinstance(target, ast.Attribute):
                    attr = target.attr
                elif isinstance(target, ast.Name):
                    attr = target.id
                if attr in ("tool", "resource", "prompt"):
                    yield node
                    break


def collect_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = fn.args
    names: set[str] = set()
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        if a.arg not in ("self", "cls"):
            names.add(a.arg)
    return names


# ---------- helpers for recognizing callees ----------


def _callee_chain(node: ast.expr) -> str | None:
    """Return 'subprocess.Popen' / 'os.system' / 'pickle.loads' / …"""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _kwarg(call: ast.Call, key: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == key:
            return kw.value
    return None


def _kwarg_bool(call: ast.Call, key: str) -> bool | None:
    v = _kwarg(call, key)
    if isinstance(v, ast.Constant) and isinstance(v.value, bool):
        return v.value
    return None


def _arg_refs_param(arg: ast.expr, params: set[str]) -> bool:
    """Does the argument expression reference any of these parameter names?"""
    for sub in ast.walk(arg):
        if isinstance(sub, ast.Name) and sub.id in params:
            return True
    return False


def _any_arg_tainted(call: ast.Call, params: set[str]) -> bool:
    return any(_arg_refs_param(a, params) for a in call.args) or any(
        _arg_refs_param(kw.value, params) for kw in call.keywords if kw.value is not None
    )


# ---------- sink signature maps ----------

# callee_chain → (category, severity, title, description, remediation, cwe, refs)
_UNSAFE_DESER_SINKS = {
    "pickle.loads": (
        "CWE-502",
        "pickle.loads deserializes untrusted data as arbitrary Python objects",
        "Use a safe format (JSON, msgpack) or require a cryptographic signature.",
    ),
    "pickle.load": (
        "CWE-502",
        "pickle.load deserializes untrusted data as arbitrary Python objects",
        "Use a safe format (JSON, msgpack) or require a cryptographic signature.",
    ),
    "marshal.loads": (
        "CWE-502",
        "marshal.loads can execute arbitrary Python code on deserialize",
        "Do not deserialize untrusted marshal payloads.",
    ),
    "yaml.load": (
        "CWE-502",
        "yaml.load without SafeLoader can construct arbitrary Python objects",
        "Use yaml.safe_load or explicit SafeLoader.",
    ),
}

_SHELL_INJECTION_SINKS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
_SUBPROCESS_SINKS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}
_EVAL_SINKS = {"eval", "exec"}

_HTTP_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "urllib.request.urlopen",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
    "httpx.request",
}
_HTTP_METHOD_ATTRS = {"get", "post", "put", "delete", "patch", "head", "request"}  # for client objects

_FILE_OPEN_SINKS = {"open"}
_PATH_OPEN_ATTRS = {"open", "read_text", "read_bytes", "write_text", "write_bytes"}


# ---------- rule functions ----------


def rule_unsafe_deserialization(ctx: CodeContext) -> Iterable[Finding]:
    out: list[Finding] = []
    for call in _walk_calls(ctx.func_node):
        chain = _callee_chain(call.func)
        if chain not in _UNSAFE_DESER_SINKS:
            continue
        if chain == "yaml.load" and _kwarg(call, "Loader") is not None:
            # If an explicit Loader is passed, may still be unsafe (yaml.Loader), but skip safe-loader variant:
            loader_node = _kwarg(call, "Loader")
            if (
                isinstance(loader_node, ast.Attribute) and loader_node.attr == "SafeLoader"
            ) or (isinstance(loader_node, ast.Name) and loader_node.id == "SafeLoader"):
                continue
        cwe, desc, rem = _UNSAFE_DESER_SINKS[chain]
        tainted = _any_arg_tainted(call, ctx.param_names)
        sev = Severity.CRITICAL if tainted else Severity.HIGH
        conf = Confidence.LIKELY if tainted else Confidence.SUSPECTED
        out.append(
            Finding(
                rule_id="MCP-DES-001",
                title=f"Unsafe deserialization via {chain}",
                category=Category.DESERIALIZATION,
                severity=sev,
                confidence=conf,
                description=desc + (" — call takes a tool parameter." if tainted else ""),
                remediation=rem,
                evidence=[Evidence(location=ctx.loc(call), snippet=ctx.snippet(call))],
                cwe=[cwe],
                references=[
                    "https://owasp.org/www-project-mcp-top-10/2025/MCP04-2025%E2%80%93Software-Supply-Chain-Attacks&Dependency-Tampering",
                ],
            )
        )
    return out


def rule_command_injection(ctx: CodeContext) -> Iterable[Finding]:
    out: list[Finding] = []
    for call in _walk_calls(ctx.func_node):
        chain = _callee_chain(call.func)

        # os.system / os.popen / subprocess.getoutput — always shell.
        if chain in _SHELL_INJECTION_SINKS:
            tainted = _any_arg_tainted(call, ctx.param_names)
            conf = Confidence.LIKELY if tainted else Confidence.SUSPECTED
            sev = Severity.CRITICAL if tainted else Severity.HIGH
            out.append(
                _cmdi_finding(
                    ctx, call, chain,
                    f"{chain} spawns a shell; argument becomes a shell command.",
                    sev=sev, conf=conf,
                )
            )
            continue

        # subprocess.* with shell=True.
        if chain in _SUBPROCESS_SINKS:
            shell = _kwarg_bool(call, "shell")
            if shell is True:
                tainted = _any_arg_tainted(call, ctx.param_names)
                conf = Confidence.CONFIRMED if not tainted else Confidence.LIKELY
                sev = Severity.CRITICAL if tainted else Severity.HIGH
                out.append(
                    _cmdi_finding(
                        ctx, call, chain,
                        f"{chain}(..., shell=True) — any user-controlled segment is shell-injectable.",
                        sev=sev, conf=conf,
                    )
                )
            # shell=False but string-concat / format / f-string in cmd arg is also risky.
            elif call.args:
                cmd = call.args[0]
                if _is_string_concatish(cmd) and _arg_refs_param(cmd, ctx.param_names):
                    out.append(
                        _cmdi_finding(
                            ctx, call, chain,
                            f"{chain} invoked with a dynamically-assembled command string containing a tool parameter.",
                            sev=Severity.HIGH, conf=Confidence.LIKELY,
                        )
                    )
            continue

        # eval / exec
        if chain in _EVAL_SINKS:
            tainted = _any_arg_tainted(call, ctx.param_names)
            conf = Confidence.CONFIRMED if not tainted else Confidence.LIKELY
            sev = Severity.CRITICAL if tainted else Severity.HIGH
            out.append(
                _cmdi_finding(
                    ctx, call, chain,
                    f"{chain}() executes arbitrary Python; deadly when fed tool input.",
                    sev=sev, conf=conf,
                )
            )
    return out


def _cmdi_finding(
    ctx: CodeContext,
    call: ast.Call,
    chain: str,
    desc: str,
    sev: Severity,
    conf: Confidence,
) -> Finding:
    return Finding(
        rule_id="MCP-CMDI-001",
        title=f"Command / code execution sink: {chain}",
        category=Category.COMMAND_INJECTION,
        severity=sev,
        confidence=conf,
        description=desc,
        remediation=(
            "Never pass shell=True. Use shlex-split arg lists, or a typed library call. "
            "Validate the parameter against an allowlist before use."
        ),
        evidence=[Evidence(location=ctx.loc(call), snippet=ctx.snippet(call))],
        cwe=["CWE-78", "CWE-94"],
        owasp_mcp="MCP05:2025",
        references=[
            "https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/",
            "https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html",
        ],
    )


def _is_string_concatish(node: ast.AST) -> bool:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call):
        chain = _callee_chain(node.func)
        if chain and chain.endswith(".format"):
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):  # "%s" % x
        return True
    return False


def rule_path_traversal(ctx: CodeContext) -> Iterable[Finding]:
    out: list[Finding] = []
    for call in _walk_calls(ctx.func_node):
        chain = _callee_chain(call.func)
        is_open_like = (
            chain in _FILE_OPEN_SINKS
            or (chain and chain.split(".")[-1] in _PATH_OPEN_ATTRS and chain != "open")
        )
        if not is_open_like:
            continue
        if not call.args:
            continue
        path_arg = call.args[0]
        if not _arg_refs_param(path_arg, ctx.param_names):
            continue
        # Heuristic: look for a preceding realpath/startswith guard on the parameter.
        if _has_path_guard(ctx.func_node, path_arg, ctx.param_names):
            continue
        out.append(
            Finding(
                rule_id="MCP-PATH-001",
                title=f"Path-traversal exposure in {chain}",
                category=Category.PATH_TRAVERSAL,
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    f"{chain} receives a tool parameter as a path with no realpath-anchor "
                    "check visible in this function. '..' / absolute paths / symlinks escape "
                    "any intended root."
                ),
                remediation=(
                    "Resolve the path via Path(root).joinpath(p).resolve() and assert "
                    "the result is a subpath of root. Reject absolute paths and symlinks "
                    "outside the root."
                ),
                evidence=[Evidence(location=ctx.loc(call), snippet=ctx.snippet(call))],
                cwe=["CWE-22"],
                owasp_mcp="MCP06:2025",
                references=[
                    "https://snyk.io/articles/preventing-path-traversal-vulnerabilities-in-mcp-server-function-handlers/",
                ],
            )
        )
    return out


def _has_path_guard(fn: ast.AST, path_arg: ast.expr, params: set[str]) -> bool:
    """Very approximate: look anywhere in the function for .resolve() + relative_to()/startswith()."""
    saw_resolve = False
    saw_guard = False
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Attribute):
            if sub.attr == "resolve":
                saw_resolve = True
            if sub.attr in ("relative_to", "startswith", "commonpath", "is_relative_to"):
                saw_guard = True
    return saw_resolve and saw_guard


def rule_ssrf(ctx: CodeContext) -> Iterable[Finding]:
    out: list[Finding] = []
    for call in _walk_calls(ctx.func_node):
        chain = _callee_chain(call.func)
        method_attr = chain.split(".")[-1] if chain else None
        matches = chain in _HTTP_SINKS or (method_attr in _HTTP_METHOD_ATTRS and chain not in _HTTP_SINKS and _looks_like_client_call(call))
        if not matches:
            continue
        # Does the URL argument reference a param?
        url_arg = call.args[0] if call.args else _kwarg(call, "url")
        if url_arg is None:
            continue
        if not _arg_refs_param(url_arg, ctx.param_names):
            continue
        # Guard: if the function validates the URL via urlparse + allowlist, suppress.
        if _has_url_guard(ctx.func_node):
            continue
        out.append(
            Finding(
                rule_id="MCP-SSRF-001",
                title=f"SSRF exposure in {chain or 'http client call'}",
                category=Category.SSRF,
                severity=Severity.HIGH,
                confidence=Confidence.LIKELY,
                description=(
                    "Outbound HTTP call uses a URL derived from a tool parameter without a "
                    "visible host allowlist. Attackers can pivot to internal hosts, "
                    "169.254.169.254 (cloud IMDS), file://, or gopher://."
                ),
                remediation=(
                    "Parse the URL, assert scheme in {https}, resolve the hostname and reject "
                    "private / link-local / loopback addresses. Prefer a pre-approved host allowlist."
                ),
                evidence=[Evidence(location=ctx.loc(call), snippet=ctx.snippet(call))],
                cwe=["CWE-918"],
                owasp_mcp="MCP07:2025",
                references=[
                    "https://www.descope.com/blog/post/mcp-vulnerabilities",
                    "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices",
                ],
            )
        )
    return out


def _looks_like_client_call(call: ast.Call) -> bool:
    # e.g., client.get(url=...), session.post(url)
    if not isinstance(call.func, ast.Attribute):
        return False
    # has a url-ish first positional or 'url' kwarg
    return bool(call.args) or _kwarg(call, "url") is not None


def _has_url_guard(fn: ast.AST) -> bool:
    saw_parse = False
    saw_blocklist = False
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Attribute) and sub.attr in ("urlparse", "gethostbyname"):
            saw_parse = True
        if isinstance(sub, ast.Call):
            chain = _callee_chain(sub.func)
            if chain in ("ipaddress.ip_address", "ipaddress.ip_network"):
                saw_blocklist = True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if sub.value in ("127.0.0.1", "169.254.169.254", "::1") or sub.value.startswith("10."):
                saw_blocklist = True
    return saw_parse and saw_blocklist


def rule_env_dump(tree: ast.AST, workdir: Path, source_file: Path) -> Iterable[Finding]:
    """Flag suspicious module-level iteration over os.environ with outbound calls in the same file."""
    iterates_env = False
    has_outbound = False
    env_evidence: ast.AST | None = None
    for node in ast.walk(tree):
        # for k, v in os.environ.items(): ...  OR  dict(os.environ) at module level
        if isinstance(node, ast.For) and _refers_to_os_environ(node.iter):
            iterates_env = True
            env_evidence = node
        if isinstance(node, ast.Call):
            callee = _callee_chain(node.func)
            if callee == "dict" and node.args and _refers_to_os_environ(node.args[0]):
                iterates_env = True
                env_evidence = node
            if callee in _HTTP_SINKS or callee in ("requests.post", "httpx.post", "urllib.request.urlopen"):
                has_outbound = True
    if iterates_env and has_outbound and env_evidence is not None:
        rel = _safe_relpath(source_file, workdir)
        return [
            Finding(
                rule_id="MCP-EXF-001",
                title="Possible environment exfiltration pattern",
                category=Category.CREDENTIAL_EXFIL,
                severity=Severity.CRITICAL,
                confidence=Confidence.SUSPECTED,
                description=(
                    "Module reads os.environ and also makes outbound HTTP calls. This is the "
                    "shape of known credential-exfiltration MCP servers."
                ),
                remediation=(
                    "Do not read arbitrary environment at import. Read only the declared "
                    "variables you need, and never include env in outbound requests."
                ),
                evidence=[
                    Evidence(
                        location=f"{rel}:{getattr(env_evidence, 'lineno', 0)}",
                        snippet=ast.unparse(env_evidence)[:300] if hasattr(ast, "unparse") else None,
                    )
                ],
                cwe=["CWE-522", "CWE-200"],
                owasp_mcp="MCP01:2025",
                references=[
                    "https://www.doppler.com/guides/mcp-server-security-risks-attack-scenarios/malicious-code-and-credential-theft",
                    "https://cyata.ai/blog/whispering-secrets-loudly-inside-mcps-quiet-crisis-of-credential-exposure/",
                ],
            )
        ]
    return []


def _refers_to_os_environ(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr == "environ":
            return True
        if isinstance(sub, ast.Name) and sub.id == "environ":
            return True
    return False


def rule_logger_arg_leak(ctx: CodeContext) -> Iterable[Finding]:
    """logger.*(…, headers=..., args=..., env=...) or logger.debug(request) patterns."""
    out: list[Finding] = []
    for call in _walk_calls(ctx.func_node):
        chain = _callee_chain(call.func)
        if not chain:
            continue
        last = chain.split(".")[-1]
        if last not in ("debug", "info", "warning", "error", "exception", "log", "print"):
            continue
        # Only interesting on logger/print-ish targets.
        head = chain.split(".")[0].lower()
        if head not in ("logger", "logging", "log", "print", "self"):
            continue
        if not _any_arg_tainted(call, ctx.param_names):
            continue
        # Heuristic: if there's a 'redact'/'mask'/'sanitize' guard nearby in the function, skip.
        if _has_redact_guard(ctx.func_node):
            continue
        out.append(
            Finding(
                rule_id="MCP-LOG-001",
                title="Tool parameter logged without redaction",
                category=Category.LOGGING_LEAK,
                severity=Severity.MEDIUM,
                confidence=Confidence.SUSPECTED,
                description=(
                    f"{chain}() is called with a tool parameter argument. If the parameter "
                    "ever carries secrets, they will land in logs / telemetry."
                ),
                remediation=(
                    "Pass a redacted view of the parameter (mask tokens, drop headers), or "
                    "log a summary only."
                ),
                evidence=[Evidence(location=ctx.loc(call), snippet=ctx.snippet(call))],
                cwe=["CWE-532"],
                owasp_mcp="MCP01:2025",
                references=[
                    "https://owasp.org/www-project-mcp-top-10/2025/MCP01-2025-Token-Mismanagement-and-Secret-Exposure",
                ],
            )
        )
    return out


def _has_redact_guard(fn: ast.AST) -> bool:
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Attribute) and sub.attr in ("redact", "sanitize", "mask", "scrub"):
            return True
        if isinstance(sub, ast.Name) and sub.id in ("redact", "sanitize", "mask", "scrub"):
            return True
    return False


def rule_sql_injection(ctx: CodeContext) -> Iterable[Finding]:
    out: list[Finding] = []
    for call in _walk_calls(ctx.func_node):
        chain = _callee_chain(call.func)
        if not chain:
            continue
        last = chain.split(".")[-1]
        if last not in ("execute", "executemany", "executescript"):
            continue
        if not call.args:
            continue
        q = call.args[0]
        if _is_string_concatish(q) and _arg_refs_param(q, ctx.param_names):
            out.append(
                Finding(
                    rule_id="MCP-SQLI-001",
                    title=f"SQL built via string concatenation in {chain}",
                    category=Category.INJECTION_DB,
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    description=(
                        "Query appears assembled from a tool parameter via concatenation/format. "
                        "Use parameterized queries."
                    ),
                    remediation=(
                        "Pass bind parameters as the second argument to execute(); never embed "
                        "parameters with + / .format / f-strings."
                    ),
                    evidence=[Evidence(location=ctx.loc(call), snippet=ctx.snippet(call))],
                    cwe=["CWE-89"],
                    references=[
                        "https://www.trendmicro.com/en_us/research/25/f/why-a-classic-mcp-server-vulnerability-can-undermine-your-entire-ai-agent.html",
                    ],
                )
            )
    return out


def _walk_calls(node: ast.AST) -> Iterable[ast.Call]:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            yield sub
