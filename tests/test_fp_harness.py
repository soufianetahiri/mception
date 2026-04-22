"""Fixture-based precision/recall harness.

Each directory under ``tests/fixtures/servers/`` is a minimal hand-written
MCP-server fixture that pins one of the false-positive (or true-positive)
classes we care about. An ``expected.json`` alongside describes the
must-contain and must-not-contain rule ids so the audit output is graded
deterministically.

The harness runs offline (``settings.offline_mode = True``) so OSV and other
network-backed engines are skipped — we only care about rule precision here.

Running the harness also prints a one-line precision summary:

    harness: N fixtures, M assertions, K failures

which the dev command surfaces.
"""

from __future__ import annotations

import json
import shutil
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from mception.config import settings
from mception.engines.dispatch import run_audit

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "servers"


def _discover_fixtures() -> list[Path]:
    if not FIXTURES_DIR.is_dir():
        return []
    return sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir() and (p / "expected.json").is_file())


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """Force offline mode so the harness never hits the network."""
    monkeypatch.setattr(settings, "offline_mode", True)


@pytest.fixture(autouse=True)
def _isolate_data_dir(tmp_path, monkeypatch):
    """Redirect data_dir so fixture runs don't clobber a dev's real baselines."""
    monkeypatch.setattr(settings, "data_dir", tmp_path / "mception-data")


def _finding_matches(pattern: str, rule_id: str, severity: str) -> bool:
    """`pattern` is either ``RULE_ID`` or ``RULE_ID:severity``, both glob-friendly."""
    if ":" in pattern:
        rp, sp = pattern.rsplit(":", 1)
        return fnmatchcase(rule_id, rp) and fnmatchcase(severity, sp)
    return fnmatchcase(rule_id, pattern)


def _grade(expected: dict, findings: list, verdict: str) -> list[str]:
    """Return a list of assertion failures (empty = perfect grade)."""
    failures: list[str] = []
    must_contain = expected.get("must_contain") or []
    must_not = expected.get("must_not_contain") or []
    verdict_not = expected.get("verdict_not") or []

    for pat in must_contain:
        if not any(_finding_matches(pat, f.rule_id, f.severity.value) for f in findings):
            failures.append(f"missing required finding {pat!r}")
    for pat in must_not:
        hits = [f for f in findings if _finding_matches(pat, f.rule_id, f.severity.value)]
        if hits:
            failures.append(
                f"unexpected finding {pat!r} matched: "
                + ", ".join(f"{h.rule_id}:{h.severity.value}" for h in hits)
            )
    for bad in verdict_not:
        if verdict == bad:
            failures.append(f"verdict should not be {bad!r}")
    return failures


def _stage(fixture_dir: Path, tmp_path: Path) -> Path:
    """Copy a fixture out of ``tests/…`` into *tmp_path* so engines that skip
    ``tests/`` path components (e.g. the python SAST walker) actually scan it."""
    dst = tmp_path / fixture_dir.name
    shutil.copytree(fixture_dir, dst)
    return dst


_FIXTURES = _discover_fixtures()


@pytest.mark.skipif(not _FIXTURES, reason="no fixtures discovered")
@pytest.mark.parametrize("fixture_dir", _FIXTURES, ids=lambda p: p.name)
async def test_fixture(fixture_dir: Path, tmp_path: Path):
    expected = json.loads((fixture_dir / "expected.json").read_text(encoding="utf-8"))
    staged = _stage(fixture_dir, tmp_path)
    report = await run_audit(str(staged), target_kind="local")
    failures = _grade(expected, report.findings, report.score.verdict.value)
    assert not failures, (
        f"{fixture_dir.name}: "
        + "; ".join(failures)
        + f"\n  actual findings: {[f.rule_id + ':' + f.severity.value for f in report.findings]}"
        + f"\n  verdict: {report.score.verdict.value}"
    )


async def test_harness_summary(tmp_path: Path, capsys):
    """Single emitter of the ``harness: X fixtures, Y assertions, Z failures``
    line that the dev command consumes."""
    fixtures = _discover_fixtures()
    assertions = failures = 0
    for fx in fixtures:
        expected = json.loads((fx / "expected.json").read_text(encoding="utf-8"))
        n_assertions = (
            len(expected.get("must_contain") or [])
            + len(expected.get("must_not_contain") or [])
            + len(expected.get("verdict_not") or [])
        )
        staged = _stage(fx, tmp_path)
        report = await run_audit(str(staged), target_kind="local")
        fs = _grade(expected, report.findings, report.score.verdict.value)
        assertions += n_assertions
        failures += len(fs)

    print(f"harness: {len(fixtures)} fixtures, {assertions} assertions, {failures} failures")
    captured = capsys.readouterr()
    assert "harness:" in captured.out
    assert failures == 0, captured.out
