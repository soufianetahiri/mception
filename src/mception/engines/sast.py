"""SAST engine: walks Python source, applies code_rules, optionally runs Bandit."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity
from ..rules.code_rules import (
    CodeContext,
    collect_import_bindings,
    collect_params,
    iter_tool_handlers,
    rule_command_injection,
    rule_env_dump,
    rule_logger_arg_leak,
    rule_path_traversal,
    rule_sql_injection,
    rule_ssrf,
    rule_unsafe_deserialization,
)
from ..rules.go_rules import GO_EXTS, _go_sources, scan_go_file
from ..rules.node_rules import NODE_EXTS, _node_sources, scan_node_file
from ..rules.ruby_rules import RUBY_EXTS, _ruby_sources, scan_ruby_file
from ..rules.rust_rules import RUST_EXTS, _rust_sources, scan_rust_file
from ..rules.surface import classify_surface
from .base import EngineResult, TargetContext

# TODO: Java SAST rules (Spring / Gradle / Maven surface) deferred — too much
# framework surface for the current tranche.


class SASTEngine:
    name = "sast"

    async def run(self, target_ctx: TargetContext) -> EngineResult:
        result = EngineResult(engine=self.name)
        if target_ctx.workdir is None:
            result.inconclusive = True
            result.notes.append("SAST needs a workdir.")
            return result

        findings: list[Finding] = []
        scanned = 0
        for path in _python_sources(target_ctx.workdir):
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=str(path))
            except SyntaxError:
                continue
            scanned += 1
            # Module-level rules (once per file).
            findings.extend(rule_env_dump(tree, target_ctx.workdir, path))
            # File-level gating context reused across every tool-handler ctx.
            bindings = collect_import_bindings(tree)
            surface = classify_surface(path, src, target_ctx.workdir)
            # Tool-handler rules.
            for fn in iter_tool_handlers(tree):
                ctx = CodeContext(
                    workdir=target_ctx.workdir,
                    source_file=path,
                    func_node=fn,
                    param_names=collect_params(fn),
                    bindings=bindings,
                    surface=surface,
                )
                findings.extend(rule_unsafe_deserialization(ctx))
                findings.extend(rule_command_injection(ctx))
                findings.extend(rule_path_traversal(ctx))
                findings.extend(rule_ssrf(ctx))
                findings.extend(rule_logger_arg_leak(ctx))
                findings.extend(rule_sql_injection(ctx))

        # Node / TS.
        node_count = 0
        for path in _node_sources(target_ctx.workdir):
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            node_count += 1
            findings.extend(scan_node_file(path, src, target_ctx.workdir))

        # Go.
        go_count = 0
        for path in _go_sources(target_ctx.workdir):
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            go_count += 1
            findings.extend(scan_go_file(path, src, target_ctx.workdir))

        # Rust.
        rust_count = 0
        for path in _rust_sources(target_ctx.workdir):
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            rust_count += 1
            findings.extend(scan_rust_file(path, src, target_ctx.workdir))

        # Ruby.
        ruby_count = 0
        for path in _ruby_sources(target_ctx.workdir):
            try:
                src = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(src) > 2_000_000:
                continue
            ruby_count += 1
            findings.extend(scan_ruby_file(path, src, target_ctx.workdir))

        # Optional external Bandit sweep; skipped silently if not installed.
        bandit_findings = _run_bandit(target_ctx.workdir)
        findings.extend(bandit_findings)

        result.findings = findings
        result.notes.append(
            f"SAST scanned {scanned} py / {node_count} js-ts / {go_count} go / "
            f"{rust_count} rs / {ruby_count} rb files; emitted {len(findings)} findings "
            f"({'bandit available' if bandit_findings or shutil.which('bandit') else 'bandit not installed; skipped'})."
        )
        return result


def _python_sources(root: Path):
    skip = {".git", "node_modules", "__pycache__", "dist", "build", ".venv", "venv", "tests", "test"}
    for p in root.rglob("*.py"):
        if any(part in skip for part in p.parts):
            continue
        yield p


# ---------- Bandit wrapper ----------

_BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _run_bandit(workdir: Path) -> list[Finding]:
    if shutil.which("bandit") is None:
        return []
    try:
        proc = subprocess.run(  # noqa: S603
            [
                "bandit",
                "-r",
                str(workdir),
                "-f",
                "json",
                "-q",
                "--skip",
                "B101",  # assert_used in tests
            ],
            capture_output=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    try:
        data = json.loads(proc.stdout or b"{}")
    except json.JSONDecodeError:
        return []
    results = data.get("results", [])
    out: list[Finding] = []
    for r in results:
        sev = _BANDIT_SEVERITY_MAP.get(r.get("issue_severity", "").upper(), Severity.LOW)
        conf_raw = r.get("issue_confidence", "").upper()
        conf = {
            "HIGH": Confidence.LIKELY,
            "MEDIUM": Confidence.SUSPECTED,
            "LOW": Confidence.SUSPECTED,
        }.get(conf_raw, Confidence.SUSPECTED)
        test_id = r.get("test_id") or "B000"
        out.append(
            Finding(
                rule_id=f"BANDIT-{test_id}",
                title=f"Bandit: {r.get('issue_text', 'issue')}",
                category=_category_for_bandit(test_id),
                severity=sev,
                confidence=conf,
                description=r.get("issue_text", ""),
                remediation="See Bandit docs for this test id.",
                evidence=[
                    Evidence(
                        location=f"{r.get('filename')}:{r.get('line_number', 0)}",
                        snippet=(r.get("code") or "").strip()[:300],
                    )
                ],
                cwe=[f"CWE-{r.get('issue_cwe', {}).get('id', 'UNK')}"] if r.get("issue_cwe") else [],
                references=[r.get("more_info", "")] if r.get("more_info") else [],
            )
        )
    return out


def _category_for_bandit(test_id: str) -> Category:
    # Rough mapping so Bandit findings sort sensibly in score breakdown.
    tid = test_id.upper()
    if tid in ("B602", "B603", "B604", "B605", "B606", "B607", "B609"):
        return Category.COMMAND_INJECTION
    if tid in ("B301", "B302", "B303", "B304", "B305", "B306", "B307", "B308", "B310"):
        return Category.DESERIALIZATION
    if tid in ("B309", "B311"):
        return Category.PROVENANCE
    family = tid[:3]
    if family == "B10":
        return Category.CREDENTIAL_EXFIL
    if family == "B20":
        return Category.DESERIALIZATION
    if family in ("B50", "B70"):
        return Category.AUTH
    return Category.META
