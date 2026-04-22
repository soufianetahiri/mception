"""Report rendering: Markdown, JSON, SARIF."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from .findings import Finding, Severity
from .scoring import ScoreResult, Verdict

VERDICT_BADGE = {
    Verdict.SAFE: "✅ SAFE TO USE",
    Verdict.CAUTION: "⚠️  USE WITH CAUTION",
    Verdict.UNSAFE: "❌ UNSAFE TO USE",
    Verdict.INCONCLUSIVE: "❓ INCONCLUSIVE",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class AuditReport(BaseModel):
    audit_id: str
    target: str
    target_kind: str  # "server" | "config"
    generated_at: str
    mception_version: str
    profile: str
    score: ScoreResult
    findings: list[Finding]
    suppressed_findings: list[Finding] = []
    notes: list[str] = []

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_json(report: AuditReport, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def to_markdown(report: AuditReport) -> str:
    s = report.score
    lines: list[str] = []
    lines.append(f"# mception audit — {report.target}")
    lines.append("")
    lines.append(f"**Verdict:** {VERDICT_BADGE[s.verdict]}")
    lines.append(f"**Score:** {s.score}/100")
    lines.append(f"**Reason:** {s.verdict_reason}")
    lines.append("")
    lines.append(
        f"- Audit ID: `{report.audit_id}`  \n"
        f"- Target: `{report.target}` ({report.target_kind})  \n"
        f"- Profile: `{report.profile}`  \n"
        f"- Generated: {report.generated_at}  \n"
        f"- mception: v{report.mception_version}"
    )
    lines.append("")
    lines.append("## Score breakdown")
    lines.append("")
    lines.append(f"- Total penalty: **{s.breakdown.total_penalty}**")
    lines.append(f"- Findings: **{s.breakdown.finding_count}**")
    lines.append("- By severity:")
    for sev in SEVERITY_ORDER:
        c = s.breakdown.by_severity.get(sev.value, 0)
        if c:
            lines.append(f"  - {sev.value}: {c}")
    if s.breakdown.by_category:
        lines.append("- By category (penalty points):")
        for cat, pen in sorted(s.breakdown.by_category.items(), key=lambda kv: -kv[1]):
            lines.append(f"  - `{cat}`: {pen}")
    lines.append("")

    if not report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("_None._")
    else:
        sev_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
        ordered = sorted(report.findings, key=lambda f: (sev_rank[f.severity], f.rule_id))
        lines.append("## Findings")
        lines.append("")
        for f in ordered:
            lines.append(f"### [{f.severity.value.upper()}] {f.rule_id} — {f.title}")
            lines.append("")
            lines.append(
                f"- Category: `{f.category.value}`  \n"
                f"- Confidence: `{f.confidence.value}`"
                + (f"  \n- Target: `{f.target_component}`" if f.target_component else "")
                + (f"  \n- OWASP MCP: `{f.owasp_mcp}`" if f.owasp_mcp else "")
                + (f"  \n- CWE: {', '.join(f.cwe)}" if f.cwe else "")
            )
            lines.append("")
            lines.append(f.description)
            lines.append("")
            if f.evidence:
                lines.append("**Evidence**")
                lines.append("")
                for e in f.evidence:
                    lines.append(f"- `{e.location}`")
                    if e.snippet:
                        snip = e.snippet if len(e.snippet) < 400 else e.snippet[:400] + "…"
                        fence = "```"
                        lines.append(f"  {fence}")
                        for ln in snip.splitlines():
                            lines.append(f"  {ln}")
                        lines.append(f"  {fence}")
                lines.append("")
            lines.append(f"**Remediation.** {f.remediation}")
            if f.references:
                lines.append("")
                lines.append("**References**")
                for r in f.references:
                    lines.append(f"- {r}")
            lines.append("")
    if report.notes:
        lines.append("## Notes")
        lines.append("")
        for n in report.notes:
            lines.append(f"- {n}")
        lines.append("")
    return "\n".join(lines)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(report: AuditReport) -> str:
    """SARIF 2.1.0 output for CI integration (GitHub code scanning, etc.)."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.findings:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": f.references[0] if f.references else "",
                "properties": {
                    "category": f.category.value,
                    "cwe": f.cwe,
                    "owasp_mcp": f.owasp_mcp or "",
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            },
        )
        locs: list[dict[str, Any]] = []
        for ev in f.evidence:
            locs.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": ev.location},
                    }
                }
            )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.description},
                "locations": locs
                or [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.target},
                        }
                    }
                ],
                "properties": {
                    "confidence": f.confidence.value,
                    "severity": f.severity.value,
                },
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mception",
                        "version": report.mception_version,
                        "informationUri": "https://github.com/mception/mception",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "verdict": report.score.verdict.value,
                    "score": report.score.score,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)
