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

    has_confirmed_critical_likely = False
    has_confirmed_high_hardfail = False

    # Per-(package, version) cap for dependency_vuln: one vulnerable release version
    # often triggers 5–15 OSV advisories (e.g. vite@6.0.0). Without a per-package cap,
    # a single dependency drives the score to 0. Policy: cap each (pkg,ver) bucket at
    # one "HIGH + CONFIRMED" equivalent (= 60) for runtime deps, or one "LOW" (= 5)
    # for dev-only deps — 11 CVEs in a build tool is one signal, not eleven.
    # Upgrading the one version fixes them all.
    dep_buckets: dict[tuple[str, str], float] = {}
    dep_scopes: dict[tuple[str, str], str] = {}

    for f in findings:
        pen = SEVERITY_WEIGHT[f.severity] * CONFIDENCE_MULT[f.confidence]
        by_sev[f.severity] += 1

        if f.category == Category.DEPENDENCY_VULN and f.evidence:
            ev = f.evidence[0]
            pkg = ev.location or ""
            ver = str(ev.extra.get("version", "")) if ev.extra else ""
            scope = str(ev.extra.get("scope", "runtime")) if ev.extra else "runtime"
            key = (pkg, ver)
            dep_buckets[key] = dep_buckets.get(key, 0.0) + pen
            # Track scope: if any finding in the bucket is runtime, treat bucket as runtime.
            if dep_scopes.get(key) != "runtime":
                dep_scopes[key] = scope
        else:
            by_cat[f.category] = by_cat.get(f.category, 0.0) + pen

        # Auto-fail gate: require high confidence for a critical to unilaterally fail.
        # "Suspected critical" should still weigh on the score but not bypass it.
        if f.severity == Severity.CRITICAL and f.confidence in (
            Confidence.CONFIRMED,
            Confidence.LIKELY,
        ):
            has_confirmed_critical_likely = True
        if (
            f.confidence == Confidence.CONFIRMED
            and f.severity == Severity.HIGH
            and f.category in HARD_FAIL_CATEGORIES
        ):
            has_confirmed_high_hardfail = True

    # Fold capped dep_vuln buckets back into the category total.
    _RUNTIME_DEP_CAP = SEVERITY_WEIGHT[Severity.HIGH]  # = 60
    _DEV_DEP_CAP = SEVERITY_WEIGHT[Severity.LOW]  # = 5
    dep_vuln_total = 0.0
    for key, pen in dep_buckets.items():
        cap = _RUNTIME_DEP_CAP if dep_scopes.get(key, "runtime") == "runtime" else _DEV_DEP_CAP
        dep_vuln_total += min(pen, cap)
    if dep_vuln_total:
        by_cat[Category.DEPENDENCY_VULN] = by_cat.get(Category.DEPENDENCY_VULN, 0.0) + dep_vuln_total

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

    if has_confirmed_critical_likely or has_confirmed_high_hardfail:
        verdict = Verdict.UNSAFE
        reason = "High-confidence critical finding or confirmed hard-fail category (cred exfil, RCE, rug-pull, tool poisoning)."
    elif score < 60:
        verdict = Verdict.UNSAFE
        reason = f"Score {score:.1f} below 60."
    elif score < 85 or by_sev[Severity.HIGH] > 0:
        verdict = Verdict.CAUTION
        reason = f"Score {score:.1f} in caution band or high-severity findings present."
    else:
        verdict = Verdict.SAFE
        reason = f"Score {score:.1f} and no high/critical findings."

    return ScoreResult(score=round(score, 1), verdict=verdict, verdict_reason=reason, breakdown=breakdown)
