"""Scoring + verdict tests. These are the contract the whole tool hinges on."""

from __future__ import annotations

from mception.findings import Category, Confidence, Finding, Severity
from mception.scoring import Verdict, score_findings


def _f(sev: Severity, conf: Confidence, cat: Category = Category.META) -> Finding:
    return Finding(
        rule_id="TEST-000",
        title="t",
        category=cat,
        severity=sev,
        confidence=conf,
        description="d",
        remediation="r",
    )


def test_empty_findings_is_safe():
    r = score_findings([])
    assert r.verdict == Verdict.SAFE
    assert r.score == 100.0


def test_inconclusive_flag_forces_verdict():
    r = score_findings([], inconclusive=True)
    assert r.verdict == Verdict.INCONCLUSIVE


def test_confirmed_critical_is_unsafe():
    r = score_findings([_f(Severity.CRITICAL, Confidence.CONFIRMED, Category.COMMAND_INJECTION)])
    assert r.verdict == Verdict.UNSAFE


def test_confirmed_high_hardfail_is_unsafe():
    r = score_findings([_f(Severity.HIGH, Confidence.CONFIRMED, Category.TOOL_POISONING)])
    assert r.verdict == Verdict.UNSAFE


def test_single_suspected_medium_is_caution_or_safe():
    r = score_findings([_f(Severity.MEDIUM, Confidence.SUSPECTED)])
    assert r.verdict in (Verdict.SAFE, Verdict.CAUTION)


def test_any_high_pushes_into_caution_not_safe():
    r = score_findings([_f(Severity.HIGH, Confidence.SUSPECTED)])
    # High × suspected = 24 penalty → score 76 → caution, AND has-high pushes caution
    assert r.verdict == Verdict.CAUTION


def test_category_cap_prevents_domination():
    # 10 critical confirmed in same category (1000 raw penalty) — capped to 120.
    findings = [
        _f(Severity.CRITICAL, Confidence.CONFIRMED, Category.DEPENDENCY_VULN) for _ in range(10)
    ]
    r = score_findings(findings)
    # But Critical × confirmed still forces UNSAFE via hard gate
    assert r.verdict == Verdict.UNSAFE
    # The cap is visible in breakdown
    assert r.breakdown.by_category["dependency_vuln"] == 1000.0  # uncapped for transparency
    # Score floors at 0
    assert r.score == 0.0


def test_score_is_deterministic():
    findings = [_f(Severity.MEDIUM, Confidence.LIKELY) for _ in range(2)]
    r1 = score_findings(findings)
    r2 = score_findings(findings)
    assert r1.model_dump() == r2.model_dump()
