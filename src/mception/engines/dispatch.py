"""Dispatcher: orchestrates fetcher + engines and produces an AuditReport."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from .. import __version__
from ..findings import Category, Confidence, Evidence, Finding, Severity
from ..report import AuditReport
from ..scoring import score_findings
from ..storage import audit_id_for, save_report
from .base import Engine, EngineResult, TargetContext
from .baseline import load_suppressions, suppress_findings
from .fetcher import FetchError, detect_kind, fetch
from .metadata import MetadataEngine
from .sast import SASTEngine
from .sca import SCAEngine
from .transport import TransportEngine


def _default_engines(profile: str) -> list[Engine]:
    if profile == "quick":
        return [MetadataEngine()]
    return [MetadataEngine(), SASTEngine(), SCAEngine(), TransportEngine()]


async def run_audit(
    target: str,
    *,
    target_kind: str | None = None,
    profile: str = "standard",
    engines: list[Engine] | None = None,
    workdir: Path | None = None,
    mcp_ctx: object | None = None,
) -> AuditReport:
    """Run the audit pipeline for one target.

    `mcp_ctx`: the FastMCP Context from the current tool call (used to drive
    the optional LLM judge via MCP sampling). None when running outside an
    MCP tool (unit tests, CLI batch runs).
    """
    k = target_kind or detect_kind(target)
    notes: list[str] = []
    fetch_cleanup: Path | None = None
    inconclusive = False
    fetch_findings: list[Finding] = []

    if workdir is None:
        try:
            fr = await fetch(target, kind=k)
            workdir = fr.workdir
            k = fr.kind
            notes.extend(fr.notes)
            if fr.cleanup:
                fetch_cleanup = fr.workdir
        except FetchError as e:
            inconclusive = True
            notes.append(f"Fetch failed: {e}")
            fetch_findings.append(
                Finding(
                    rule_id="MCP-META-001",
                    title="Could not fetch target",
                    category=Category.META,
                    severity=Severity.INFO,
                    confidence=Confidence.SUSPECTED,
                    description=f"Fetcher could not resolve target {target!r}: {e}",
                    remediation="Verify the target reference and retry; or use a local path.",
                    evidence=[Evidence(location=target)],
                )
            )

    ctx = TargetContext(
        target_ref=target, target_kind=k, workdir=workdir, mcp_ctx=mcp_ctx
    )
    engines_used = engines if engines is not None else _default_engines(profile)

    try:
        results: list[EngineResult] = (
            await asyncio.gather(*(eng.run(ctx) for eng in engines_used))
            if engines_used
            else []
        )
    finally:
        if fetch_cleanup is not None:
            shutil.rmtree(fetch_cleanup, ignore_errors=True)

    all_findings: list[Finding] = list(fetch_findings)
    for r in results:
        all_findings.extend(r.findings)
        notes.extend(r.notes)
        if r.inconclusive:
            inconclusive = True

    # If no engines were registered at all, still mark inconclusive so we don't falsely claim safe.
    if not engines_used and not fetch_findings:
        inconclusive = True
        notes.append("No engines configured for this profile.")

    # Per-rule + per-path suppressions from `.mception.yml` at the workdir root.
    # Suppressed findings are preserved on the report for audit trail but are
    # removed from the scoring input and from the main `findings` list.
    suppressions = load_suppressions(workdir) if workdir is not None else []
    kept_findings, suppressed = suppress_findings(all_findings, suppressions)

    score = score_findings(kept_findings, inconclusive=inconclusive)
    if suppressed:
        score = score.model_copy(
            update={
                "verdict_reason": (
                    f"{score.verdict_reason} "
                    f"({len(suppressed)} findings suppressed via .mception.yml)"
                )
            }
        )

    report = AuditReport(
        audit_id=audit_id_for(target, profile),
        target=target,
        target_kind=k,
        generated_at=AuditReport.now_iso(),
        mception_version=__version__,
        profile=profile,
        score=score,
        findings=kept_findings,
        suppressed_findings=suppressed,
        notes=notes,
    )
    save_report(report)
    return report
