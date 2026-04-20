"""Audit + baseline persistence. Flat JSON files under data_dir."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .config import settings
from .report import AuditReport


def audit_id_for(target: str, profile: str) -> str:
    """Deterministic audit ID. Same target+profile → same ID → idempotent reports."""
    h = hashlib.sha256(f"{target}|{profile}".encode()).hexdigest()[:16]
    return f"aud_{h}"


def _audit_path(audit_id: str) -> Path:
    return settings.ensure_data_dir() / "audits" / f"{audit_id}.json"


def save_report(report: AuditReport) -> Path:
    p = _audit_path(report.audit_id)
    p.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return p


def load_report(audit_id: str) -> AuditReport | None:
    p = _audit_path(audit_id)
    if not p.exists():
        return None
    return AuditReport.model_validate(json.loads(p.read_text(encoding="utf-8")))


def list_audits() -> list[str]:
    d = settings.ensure_data_dir() / "audits"
    return sorted(p.stem for p in d.glob("aud_*.json"))


def _baseline_path(target: str) -> Path:
    h = hashlib.sha256(target.encode()).hexdigest()[:16]
    return settings.ensure_data_dir() / "baselines" / f"bl_{h}.json"


def save_baseline(target: str, baseline: dict) -> Path:
    p = _baseline_path(target)
    p.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    return p


def load_baseline(target: str) -> dict | None:
    p = _baseline_path(target)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))
