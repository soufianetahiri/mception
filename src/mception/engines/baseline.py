"""Baselines and rug-pull diff.

A baseline is a fingerprint of a target's MCP surface:
  { "tools": { name: {"description_hash", "params_hash", "description_preview"} },
    "resources": { ... }, "prompts": { ... },
    "created_at": iso, "target": str }

On rescan, we extract the current surface, hash it the same way, and emit
MCP-RP-* findings for any add/remove/mutate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..findings import Category, Confidence, Evidence, Finding, Severity
from ..report import AuditReport
from ..storage import load_baseline, save_baseline
from .source_parse import ExtractedItem, extract_from_workdir


def build_fingerprint(items: list[ExtractedItem]) -> dict[str, Any]:
    buckets: dict[str, dict[str, dict[str, str]]] = {"tool": {}, "resource": {}, "prompt": {}, "server_instructions": {}}
    for it in items:
        if it.kind not in buckets:
            continue
        desc = it.description or ""
        params = sorted(it.extras.get("params", []))
        buckets[it.kind][it.name] = {
            "description_hash": _sha256(desc),
            "description_preview": desc[:200],
            "params_hash": _sha256("|".join(params)),
            "params": params,
        }
    return {
        "tools": buckets["tool"],
        "resources": buckets["resource"],
        "prompts": buckets["prompt"],
        "server_instructions": buckets["server_instructions"],
    }


def ensure_baseline(target: str, workdir: Path) -> tuple[dict, bool]:
    """Load or create a baseline for `target`. Returns (baseline, was_created)."""
    existing = load_baseline(target)
    if existing is not None:
        return existing, False
    items = extract_from_workdir(workdir)
    fp = build_fingerprint(items)
    fp["target"] = target
    fp["created_at"] = AuditReport.now_iso()
    save_baseline(target, fp)
    return fp, True


def diff_against_baseline(target: str, workdir: Path) -> tuple[list[Finding], dict]:
    """Compare current surface with stored baseline. Returns (findings, current_fp)."""
    baseline = load_baseline(target)
    current = build_fingerprint(extract_from_workdir(workdir))
    if baseline is None:
        # First-ever scan: persist and return no findings.
        current["target"] = target
        current["created_at"] = AuditReport.now_iso()
        save_baseline(target, current)
        return [], current

    findings: list[Finding] = []
    for kind in ("tools", "resources", "prompts", "server_instructions"):
        b = baseline.get(kind, {})
        c = current.get(kind, {})
        added = set(c) - set(b)
        removed = set(b) - set(c)
        common = set(b) & set(c)

        for name in sorted(added):
            findings.append(
                _rugpull(
                    rule_id="MCP-RP-001",
                    title=f"New {kind[:-1]} {name!r} added since baseline",
                    kind=kind,
                    name=name,
                    prev=None,
                    cur=c[name],
                    severity=Severity.HIGH,
                )
            )
        for name in sorted(removed):
            findings.append(
                _rugpull(
                    rule_id="MCP-RP-002",
                    title=f"{kind[:-1].capitalize()} {name!r} removed since baseline",
                    kind=kind,
                    name=name,
                    prev=b[name],
                    cur=None,
                    severity=Severity.MEDIUM,
                )
            )
        for name in sorted(common):
            pb, pc = b[name], c[name]
            changed_desc = pb.get("description_hash") != pc.get("description_hash")
            changed_params = pb.get("params_hash") != pc.get("params_hash")
            if changed_desc or changed_params:
                what = []
                if changed_desc:
                    what.append("description")
                if changed_params:
                    what.append("params")
                findings.append(
                    _rugpull(
                        rule_id="MCP-RP-003",
                        title=f"{kind[:-1].capitalize()} {name!r} changed ({', '.join(what)}) since baseline",
                        kind=kind,
                        name=name,
                        prev=pb,
                        cur=pc,
                        severity=Severity.HIGH,
                    )
                )
    return findings, current


def _rugpull(
    rule_id: str,
    title: str,
    kind: str,
    name: str,
    prev: dict | None,
    cur: dict | None,
    severity: Severity,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=Category.RUG_PULL,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        description=(
            "Server's published MCP surface has changed since the pinned baseline. "
            "This is the signal for a rug-pull: a benign tool redefined after adoption."
        ),
        remediation=(
            "Re-review the change. If legitimate, refresh the baseline via `refresh_baseline`. "
            "Otherwise uninstall / pin the server to a known-good version."
        ),
        evidence=[
            Evidence(
                location=f"{kind}[{name}]",
                extra={
                    "previous_description_preview": (prev or {}).get("description_preview"),
                    "current_description_preview": (cur or {}).get("description_preview"),
                    "previous_params": (prev or {}).get("params"),
                    "current_params": (cur or {}).get("params"),
                },
            )
        ],
        cwe=["CWE-494"],
        owasp_mcp="MCP08:2025",
        references=[
            "https://mcpmanager.ai/blog/mcp-rug-pull-attacks/",
            "https://acuvity.ai/rug-pulls-silent-redefinition-when-tools-turn-malicious-over-time/",
            "https://github.com/safe-agentic-framework/safe-mcp/tree/main/techniques/SAFE-T1201",
        ],
    )


def refresh_baseline(target: str, workdir: Path) -> dict:
    items = extract_from_workdir(workdir)
    fp = build_fingerprint(items)
    fp["target"] = target
    fp["created_at"] = AuditReport.now_iso()
    save_baseline(target, fp)
    return fp


def baseline_json(target: str) -> str:
    b = load_baseline(target)
    if b is None:
        return json.dumps({"error": f"no baseline for {target!r}"})
    return json.dumps(b, indent=2, sort_keys=True)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
