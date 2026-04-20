"""FastMCP server exposing mception's audit tools."""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP

from . import __version__
from .engines.baseline import baseline_json, diff_against_baseline, refresh_baseline
from .engines.cross_config import (
    load_mcp_config,
    rule_duplicate_tool_names,
    rule_lethal_trifecta,
    server_entry_to_target,
)
from .engines.dispatch import run_audit
from .engines.fetcher import FetchError, fetch
from .findings import Severity
from .report import AuditReport, to_json, to_markdown, to_sarif
from .scoring import score_findings
from .storage import audit_id_for, list_audits, load_report, save_report

mcp = FastMCP("mception")

# ---------- tools ----------


@mcp.tool()
async def audit_server(
    target: str,
    profile: str = "standard",
    target_kind: str = "local",
    ctx: Context | None = None,
) -> str:
    """Audit a single MCP server for security risks.

    target: reference to the MCP server. Forms accepted:
      - absolute path to a local directory or server entry file
      - "npm:<package>[@version]"
      - "pypi:<package>[==version]"
      - "git+https://..."
      - "docker:<image>[:tag]"
    profile: "quick" | "standard" | "deep" (engine set varies).
    target_kind: "local" | "npm" | "pypi" | "git" | "docker" (auto-detected if omitted).

    If `MCEPTION_ENABLE_LLM_JUDGE=1` is set and the host client supports MCP
    sampling, ambiguous descriptions are additionally classified by the host's
    model (advisory-only, never changes verdict alone).

    Returns a compact text summary. Full report via `get_report(audit_id)`.
    """
    report = await run_audit(
        target, target_kind=target_kind, profile=profile, mcp_ctx=ctx
    )
    s = report.score
    lines = [
        f"Audit: {report.audit_id}",
        f"Target: {report.target}",
        f"Verdict: {s.verdict.value}   Score: {s.score}/100",
        f"Reason: {s.verdict_reason}",
        f"Findings: {s.breakdown.finding_count}  "
        f"(crit={s.breakdown.by_severity.get('critical', 0)} "
        f"high={s.breakdown.by_severity.get('high', 0)} "
        f"med={s.breakdown.by_severity.get('medium', 0)} "
        f"low={s.breakdown.by_severity.get('low', 0)})",
        "",
        "Full report: call get_report('" + report.audit_id + "', format='markdown').",
    ]
    return "\n".join(lines)


@mcp.tool()
async def audit_config(
    config_path: str, profile: str = "standard", ctx: Context | None = None
) -> str:
    """Audit an entire MCP client config (claude_desktop_config.json, .mcp.json, etc.).

    Runs each server audit, applies whole-config rules (shadowing, lethal-trifecta
    composition, duplicate tool names), and returns an aggregated report.
    """
    cfg = Path(config_path)
    if not cfg.exists():
        return f"Error: config path does not exist: {config_path}"
    try:
        servers = load_mcp_config(cfg)
    except (OSError, ValueError) as e:
        return f"Error parsing config: {e}"
    if not servers:
        return f"No MCP servers declared in {config_path}."

    per_server_reports: dict[str, AuditReport] = {}
    notes: list[str] = []
    all_findings = []

    for name, entry in servers:
        target = server_entry_to_target(entry)
        if target is None:
            notes.append(f"Skipping server {name!r}: remote/url entries are not statically analyzed.")
            continue
        try:
            r = await run_audit(target, profile=profile, mcp_ctx=ctx)
        except Exception as e:  # pragma: no cover
            notes.append(f"Server {name!r} audit failed: {e}")
            continue
        per_server_reports[name] = r
        notes.append(f"Server {name!r}: {r.score.verdict.value} ({r.score.score}/100, {len(r.findings)} findings)")
        for f in r.findings:
            # Tag with server name for traceability.
            if f.target_component is None:
                f.target_component = f"server={name}"
            all_findings.append(f)

    # Cross-config rules.
    all_findings.extend(rule_duplicate_tool_names(per_server_reports))
    all_findings.extend(rule_lethal_trifecta(per_server_reports))

    score = score_findings(all_findings, inconclusive=not per_server_reports)

    report = AuditReport(
        audit_id=audit_id_for(str(cfg), profile),
        target=str(cfg),
        target_kind="config",
        generated_at=AuditReport.now_iso(),
        mception_version=__version__,
        profile=profile,
        score=score,
        findings=all_findings,
        notes=notes,
    )
    save_report(report)
    lines = [
        f"Audit: {report.audit_id}",
        f"Config: {report.target} ({len(servers)} servers declared, {len(per_server_reports)} analyzable)",
        f"Verdict: {score.verdict.value}   Score: {score.score}/100",
        f"Reason: {score.verdict_reason}",
        f"Findings: {score.breakdown.finding_count}",
        "",
        "Per-server:",
    ] + [f"  - {n}" for n in notes]
    return "\n".join(lines)


@mcp.tool()
def get_report(audit_id: str, format: str = "markdown") -> str:
    """Return the full audit report in the requested format.

    format: "markdown" | "json" | "sarif"
    """
    r = load_report(audit_id)
    if r is None:
        return f"Error: no audit with id {audit_id}. Use list_audit_ids() to enumerate."
    fmt = format.lower()
    if fmt == "json":
        return to_json(r)
    if fmt == "sarif":
        return to_sarif(r)
    return to_markdown(r)


@mcp.tool()
def list_findings(
    audit_id: str,
    severity_min: str = "info",
    category: str | None = None,
) -> str:
    """Filter and return the findings of an audit as JSON."""
    r = load_report(audit_id)
    if r is None:
        return f"Error: no audit with id {audit_id}."
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        min_idx = order.index(Severity(severity_min.lower()))
    except ValueError:
        return f"Error: severity_min must be one of {[s.value for s in order]}."
    out = [
        f
        for f in r.findings
        if order.index(f.severity) >= min_idx and (category is None or f.category.value == category)
    ]
    return json.dumps([f.model_dump(mode="json") for f in out], indent=2)


@mcp.tool()
def list_audit_ids() -> str:
    """List all persisted audit IDs on this host."""
    ids = list_audits()
    return "\n".join(ids) if ids else "(no audits yet)"


@mcp.tool()
def predicted_audit_id(target: str, profile: str = "standard") -> str:
    """Return the deterministic audit ID that would be assigned to (target, profile)."""
    return audit_id_for(target, profile)


@mcp.tool()
async def rescan_diff(target: str, target_kind: str | None = None) -> str:
    """Compare the target's current MCP surface to its pinned baseline.

    First call: creates a baseline and reports no findings.
    Subsequent calls: emits MCP-RP-001/002/003 findings on add/remove/mutate.

    Use when you suspect a rug-pull (tool definition silently changed after approval).
    """
    import shutil

    try:
        fr = await fetch(target, kind=target_kind)
    except FetchError as e:
        return f"Error: fetch failed: {e}"
    try:
        findings, _ = diff_against_baseline(target, fr.workdir)
    finally:
        if fr.cleanup:
            shutil.rmtree(fr.workdir, ignore_errors=True)
    if not findings:
        return "No drift vs. baseline (or first scan — baseline created)."
    score = score_findings(findings)
    report = AuditReport(
        audit_id=audit_id_for(target, "rescan_diff"),
        target=target,
        target_kind=fr.kind,
        generated_at=AuditReport.now_iso(),
        mception_version=__version__,
        profile="rescan_diff",
        score=score,
        findings=findings,
        notes=[f"Rug-pull diff against pinned baseline. {len(findings)} changes detected."],
    )
    save_report(report)
    return (
        f"Audit: {report.audit_id}\n"
        f"Verdict: {score.verdict.value}   Score: {score.score}/100\n"
        f"Drift findings: {len(findings)}\n"
        f"Reason: {score.verdict_reason}\n"
        f"Full report: get_report('{report.audit_id}', format='markdown')."
    )


@mcp.tool()
async def refresh_target_baseline(target: str, target_kind: str | None = None) -> str:
    """Accept the target's current MCP surface as the new baseline.

    Use after you've reviewed a rug-pull diff and concluded the change is legitimate.
    """
    import shutil

    try:
        fr = await fetch(target, kind=target_kind)
    except FetchError as e:
        return f"Error: fetch failed: {e}"
    try:
        fp = refresh_baseline(target, fr.workdir)
    finally:
        if fr.cleanup:
            shutil.rmtree(fr.workdir, ignore_errors=True)
    n = sum(len(fp.get(k, {})) for k in ("tools", "resources", "prompts"))
    return f"Baseline refreshed for {target}. Pinned {n} surface items."


# ---------- resources ----------


@mcp.resource("mception://about")
def about_resource() -> str:
    return (
        f"mception v{__version__} — MCP server that audits other MCP servers for security risks.\n"
        "Verdicts: safe_to_use | use_with_caution | unsafe_to_use | inconclusive.\n"
        "Start with the tool `audit_server(target)`."
    )


@mcp.resource("mception://report/{audit_id}")
def report_resource(audit_id: str) -> str:
    r = load_report(audit_id)
    if r is None:
        return f"(no audit {audit_id})"
    return to_markdown(r)


@mcp.resource("mception://baseline/{target}")
def baseline_resource(target: str) -> str:
    """Return the pinned baseline for a target (tool/resource/prompt fingerprints)."""
    return baseline_json(target)


# ---------- prompts ----------


@mcp.prompt()
def triage_checklist(audit_id: str) -> str:
    """Guide the user through reviewing an mception report."""
    return (
        f"Open the mception report for `{audit_id}` and walk through it:\n\n"
        "1. Read the Verdict and Reason at the top.\n"
        "2. For every CRITICAL finding: decide fix-now vs. uninstall.\n"
        "3. For every HIGH finding: decide fix, mitigate, or accept-with-note.\n"
        "4. Check the 'References' on each finding against the project's threat model.\n"
        "5. If verdict is INCONCLUSIVE: resolve the blockers (bad ref, timeout) and re-run."
    )


def main() -> None:
    """Entry point referenced by the `mception` console script."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
