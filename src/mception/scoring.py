"""Deterministic scoring and verdict derivation.

Design:
- Each finding contributes severity_weight * confidence_multiplier to a penalty sum.
- Per-category cap prevents one engine from dominating the score.
- Score = 100 - min(100, total_penalty).
- Verdict combines score with hard-fail gates (any Critical, any Confirmed RCE, etc.).
"""

from __future__ import annotations

import enum

from pydantic import BaseModel

from .findings import Category, Confidence, Finding, Severity

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 60.0,
    Severity.MEDIUM: 25.0,
    Severity.LOW: 5.0,
    Severity.INFO: 0.0,
}

CONFIDENCE_MULT: dict[Confidence, float] = {
    Confidence.CONFIRMED: 1.0,
    Confidence.LIKELY: 0.7,
    Confidence.SUSPECTED: 0.4,
}

# Cap any single category's contribution so one engine's findings don't wipe the score.
CATEGORY_CAP = 120.0

# Categories that trigger hard "Unsafe" regardless of score when at Confirmed+Critical/High.
HARD_FAIL_CATEGORIES = {
    Category.COMMAND_INJECTION,
    Category.CREDENTIAL_EXFIL,
    Category.RUG_PULL,
    Category.TOOL_POISONING,
}


class Verdict(str, enum.Enum):
    SAFE = "safe_to_use"
    CAUTION = "use_with_caution"
    UNSAFE = "unsafe_to_use"
    INCONCLUSIVE = "inconclusive"


class ScoreBreakdown(BaseModel):
    total_penalty: float
    by_category: dict[str, float]
    by_severity: dict[str, int]
    finding_count: int


class ScoreResult(BaseModel):
    score: float  # 0..100
    verdict: Verdict
    verdict_reason: str
    breakdown: ScoreBreakdown


def score_findings(findings: list[Finding], inconclusive: bool = False) -> ScoreResult:
    """Aggregate findings into a final score + verdict.

    inconclusive=True forces Verdict.INCONCLUSIVE regardless of findings — used when
    introspection/fetch failed and we cannot make a safety claim.
    """
    by_cat: dict[Category, float] = {}
    by_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)

    has_confirmed_critical = False
    has_confirmed_high_hardfail = False
    has_any_critical = False

    for f in findings:
        pen = SEVERITY_WEIGHT[f.severity] * CONFIDENCE_MULT[f.confidence]
        by_cat[f.category] = by_cat.get(f.category, 0.0) + pen
        by_sev[f.severity] += 1

        if f.severity == Severity.CRITICAL:
            has_any_critical = True
            if f.confidence == Confidence.CONFIRMED:
                has_confirmed_critical = True
        if (
            f.confidence == Confidence.CONFIRMED
            and f.severity == Severity.HIGH
            and f.category in HARD_FAIL_CATEGORIES
        ):
            has_confirmed_high_hardfail = True

    capped_total = sum(min(v, CATEGORY_CAP) for v in by_cat.values())
    score = max(0.0, 100.0 - min(100.0, capped_total))

    breakdown = ScoreBreakdown(
        total_penalty=round(capped_total, 2),
        by_category={k.value: round(v, 2) for k, v in by_cat.items()},
        by_severity={k.value: v for k, v in by_sev.items()},
        finding_count=len(findings),
    )

    if inconclusive:
        return ScoreResult(
            score=score,
            verdict=Verdict.INCONCLUSIVE,
            verdict_reason="Could not complete introspection or fetch; refusing to make a safety claim.",
            breakdown=breakdown,
        )

    if has_confirmed_critical or has_confirmed_high_hardfail:
        verdict = Verdict.UNSAFE
        reason = "Confirmed finding in a hard-fail category (critical vuln, cred exfil, RCE, rug-pull, or tool poisoning)."
    elif has_any_critical or score < 60:
        verdict = Verdict.UNSAFE
        reason = f"Score {score:.1f} below 60 or at least one critical finding present."
    elif score < 85 or by_sev[Severity.HIGH] > 0:
        verdict = Verdict.CAUTION
        reason = f"Score {score:.1f} in caution band or high-severity findings present."
    else:
        verdict = Verdict.SAFE
        reason = f"Score {score:.1f} and no high/critical findings."

    return ScoreResult(score=round(score, 1), verdict=verdict, verdict_reason=reason, breakdown=breakdown)
