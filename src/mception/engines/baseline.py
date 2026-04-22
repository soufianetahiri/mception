"""Baselines and rug-pull diff.

A baseline is a fingerprint of a target's MCP surface:
  { "tools": { name: {"description_hash", "params_hash", "description_preview"} },
    "resources": { ... }, "prompts": { ... },
    "created_at": iso, "target": str }

On rescan, we extract the current surface, hash it the same way, and emit
MCP-RP-* findings for any add/remove/mutate.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..config import settings
from ..findings import Category, Confidence, Evidence, Finding, Severity
from ..report import AuditReport
from ..storage import load_baseline, save_baseline
from .source_parse import ExtractedItem, extract_from_workdir

# Default filename for per-target suppression policy. The active filename is
# taken from `settings.suppressions_filename`; this constant exists for
# backwards-compatible imports.
SUPPRESSIONS_FILENAME = ".mception.yml"


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


# ---------------------------------------------------------------------------
# .mception.yml suppressions
# ---------------------------------------------------------------------------


@dataclass
class Suppression:
    """One suppression entry from `.mception.yml`.

    A finding is suppressed when every non-None key here matches. See
    `suppress_findings` for the matching rules.
    """

    rule_id: str | None = None
    path: str | None = None
    dependency: str | None = None
    category: str | None = None
    scope: str | None = None
    reason: str = ""
    # Raw source kept around so error messages can point back at the yaml.
    raw: dict = field(default_factory=dict)


def load_suppressions(workdir: Path | None) -> list[Suppression]:
    """Read `.mception.yml` from *workdir* and return its suppression entries.

    Returns [] if the file is missing, empty, malformed, or yaml parsing is
    unavailable. Parsing failures are silent by design — suppressions are a
    convenience feature and must never break an audit.
    """
    if workdir is None:
        return []
    cfg = workdir / settings.suppressions_filename
    if not cfg.is_file():
        return []
    try:
        raw = cfg.read_text(encoding="utf-8")
    except OSError:
        return []
    data = _parse_yaml(raw)
    if not isinstance(data, dict):
        return []
    entries = data.get("suppressions")
    if not isinstance(entries, list):
        return []
    out: list[Suppression] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        out.append(
            Suppression(
                rule_id=_str_or_none(entry.get("rule_id")),
                path=_str_or_none(entry.get("path")),
                dependency=_str_or_none(entry.get("dependency")),
                category=_str_or_none(entry.get("category")),
                scope=_str_or_none(entry.get("scope")),
                reason=str(entry.get("reason", "") or ""),
                raw=entry,
            )
        )
    return out


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _parse_yaml(src: str) -> Any:
    """Parse a yaml document. Uses PyYAML when available, else a tiny fallback.

    The fallback only understands the subset actually used in `.mception.yml`:
    a top-level mapping of keys to either scalars or lists of simple mappings.
    """
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return _parse_yaml_minimal(src)
    try:
        return yaml.safe_load(src)
    except Exception:  # pragma: no cover - defensive
        return None


def _parse_yaml_minimal(src: str) -> dict | None:
    """A tiny YAML subset parser for ``.mception.yml``.

    Handles:
      - top-level ``key: value`` scalars,
      - top-level ``key:`` followed by a list of ``- key: value`` dict items,
      - quoted and unquoted scalars (``"foo bar"``, ``'x'``, ``bare``),
      - ``#`` comments and blank lines.

    Everything else returns None. This exists purely so the feature works in
    environments without PyYAML installed — tests ship a yaml file small
    enough to fit this grammar.
    """
    root: dict[str, Any] = {}
    current_list: list[dict[str, Any]] | None = None
    current_item: dict[str, Any] | None = None
    list_indent: int | None = None

    for raw_line in src.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        # Top-level key.
        if indent == 0:
            if ":" not in stripped:
                return None
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if val == "":
                root[key] = []
                current_list = root[key]
                current_item = None
                list_indent = None
            else:
                root[key] = _unquote(val)
                current_list = None
                current_item = None
            continue

        # Inside a list.
        if current_list is None:
            continue
        if stripped.startswith("- "):
            # New list item.
            rest = stripped[2:].strip()
            current_item = {}
            current_list.append(current_item)
            list_indent = indent + 2  # position after "- "
            if rest:
                if ":" not in rest:
                    return None
                k, _, v = rest.partition(":")
                current_item[k.strip()] = _unquote(v.strip())
            continue
        # Continuation of current item.
        if current_item is None:
            continue
        if ":" not in stripped:
            continue
        k, _, v = stripped.partition(":")
        current_item[k.strip()] = _unquote(v.strip())

    return root


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def _evidence_location(f: Finding) -> str:
    if not f.evidence:
        return ""
    return f.evidence[0].location or ""


def _evidence_extra(f: Finding) -> dict:
    if not f.evidence:
        return {}
    return f.evidence[0].extra or {}


def _match_path(pattern: str, loc: str) -> bool:
    """Glob-match a suppression path against a finding evidence location.

    Evidence locations look like ``"src/foo.js:42"``. We split on ``":"`` first
    so the line/column doesn't break the match, then glob with both POSIX and
    native separators normalised.
    """
    path_part = loc.split(":", 1)[0]
    # Normalise backslashes so Windows paths match POSIX-shaped patterns from yaml.
    norm = path_part.replace("\\", "/")
    pat = pattern.replace("\\", "/")
    # Use PurePosixPath.match for `**` support.
    try:
        if PurePosixPath(norm).match(pat):
            return True
    except ValueError:
        pass
    # Fallback to fnmatch (handles simple globs without `**`).
    return fnmatch.fnmatchcase(norm, pat)


def _suppression_matches(sup: Suppression, f: Finding) -> bool:
    if sup.rule_id is not None and not fnmatch.fnmatchcase(f.rule_id, sup.rule_id):
        return False
    if sup.category is not None and f.category.value != sup.category:
        return False
    loc = _evidence_location(f)
    if sup.path is not None:
        if not loc or not _match_path(sup.path, loc):
            return False
    if sup.dependency is not None:
        if f.category != Category.DEPENDENCY_VULN:
            return False
        if loc != f"dependencies/{sup.dependency}":
            # Allow glob on the dep name for convenience.
            if not fnmatch.fnmatchcase(loc, f"dependencies/{sup.dependency}"):
                return False
    if sup.scope is not None:
        extra = _evidence_extra(f)
        if str(extra.get("scope", "")) != sup.scope:
            return False
    # At least one predicate must be specified — an empty suppression would
    # match every finding which is almost certainly a bug in the policy file.
    if all(
        v is None
        for v in (sup.rule_id, sup.path, sup.dependency, sup.category, sup.scope)
    ):
        return False
    return True


def suppress_findings(
    findings: list[Finding], suppressions: list[Suppression]
) -> tuple[list[Finding], list[Finding]]:
    """Partition *findings* by whether any suppression matches.

    Returns ``(kept, suppressed)``. Suppressed findings are copies with their
    ``suppression_reason`` populated from the first matching suppression — the
    originals are left untouched so engines can continue to rely on identity.
    """
    if not suppressions:
        return list(findings), []
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        match: Suppression | None = next(
            (s for s in suppressions if _suppression_matches(s, f)), None
        )
        if match is None:
            kept.append(f)
        else:
            suppressed.append(
                f.model_copy(update={"suppression_reason": match.reason or "(no reason given)"})
            )
    return kept, suppressed
