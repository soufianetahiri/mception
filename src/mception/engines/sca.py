"""SCA + supply-chain engine.

- Parses package.json / pyproject.toml / requirements.txt for dependencies.
- Applies static rules (postinstall, setup.py side-effects, typosquat, obfuscation).
- Optionally queries OSV.dev for known CVEs (offline-respecting).
"""

from __future__ import annotations

from typing import Any

import httpx

from ..config import settings
from ..findings import Category, Confidence, Evidence, Finding, Severity
from ..rules.supply_chain import (
    DependencySummary,
    parse_manifests,
    rule_missing_license,
    rule_no_lockfile,
    rule_obfuscation,
    rule_postinstall_scripts,
    rule_setuppy_sideeffects,
    rule_suspicious_binaries,
    rule_typosquat,
    rule_unpinned_versions,
)
from .base import EngineResult, TargetContext


class SCAEngine:
    name = "sca"

    async def run(self, target_ctx: TargetContext) -> EngineResult:
        result = EngineResult(engine=self.name)
        if target_ctx.workdir is None:
            result.inconclusive = True
            result.notes.append("SCA needs a workdir.")
            return result

        deps, info = parse_manifests(target_ctx.workdir)

        findings: list[Finding] = []
        findings.extend(rule_postinstall_scripts(target_ctx.workdir, info))
        findings.extend(rule_setuppy_sideeffects(target_ctx.workdir))
        findings.extend(rule_typosquat(deps))
        findings.extend(rule_obfuscation(target_ctx.workdir))
        findings.extend(rule_unpinned_versions(deps, info))
        findings.extend(rule_no_lockfile(target_ctx.workdir, deps, target_ctx.target_kind))
        findings.extend(rule_suspicious_binaries(target_ctx.workdir))
        findings.extend(rule_missing_license(info, target_ctx.workdir))

        if not settings.offline_mode:
            if deps:
                osv_findings, note = await _osv_query(deps)
                findings.extend(osv_findings)
                result.notes.append(note)
                reg_findings, reg_note = await _registry_signals(deps)
                findings.extend(reg_findings)
                result.notes.append(reg_note)
            phantom_findings, phantom_note = await _phantom_repo_check(info)
            findings.extend(phantom_findings)
            if phantom_note:
                result.notes.append(phantom_note)
        else:
            result.notes.append(
                f"Parsed {len(deps)} dependencies; online queries skipped (offline mode)."
            )

        result.findings = findings
        return result


_OSV_URL = "https://api.osv.dev/v1/querybatch"


_OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates": "crates.io",
}


def _demote(sev: Severity) -> Severity:
    """Drop one severity notch. Used for dev/build-scope vulns, which are not
    runtime-reachable by consumers of the package."""
    chain = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    try:
        return chain[chain.index(sev) + 1]
    except (ValueError, IndexError):
        return sev


async def _osv_query(deps: list[DependencySummary]) -> tuple[list[Finding], str]:
    """Single batch OSV request per audit. Vulnerabilities → findings.

    Queries every supported ecosystem. Vulns in dev/build/optional-scope deps are
    demoted one severity and tagged so the verdict gate doesn't treat a vite CVE
    in devDependencies the same as a live-in-production RCE.
    """
    queries: list[dict[str, Any]] = []
    query_deps: list[DependencySummary] = []
    for d in deps:
        if not d.version:
            continue
        eco = _OSV_ECOSYSTEM.get(d.ecosystem)
        if eco is None:
            continue
        queries.append(
            {
                "package": {"name": d.name, "ecosystem": eco},
                "version": _clean_version(d.version),
            }
        )
        query_deps.append(d)
    if not queries:
        return [], "OSV: no version-pinned deps to query."
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(_OSV_URL, json={"queries": queries})
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return [], "OSV: query failed (network or parse error)."
    findings: list[Finding] = []
    for dep, query, dep_result in zip(query_deps, queries, data.get("results", [])):
        vulns = dep_result.get("vulns") or []
        if not vulns:
            continue
        name = query["package"]["name"]
        version = query["version"]
        is_dev = dep.scope in ("dev", "optional", "peer")
        scope_tag = f" [{dep.scope}-only]" if is_dev else ""
        for v in vulns:
            sev = _max_osv_severity(v)
            if is_dev:
                sev = _demote(sev)
            findings.append(
                Finding(
                    rule_id=f"OSV-{v.get('id', 'UNKNOWN')}",
                    title=f"Known vulnerability in {name}=={version}{scope_tag}",
                    category=Category.DEPENDENCY_VULN,
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        (v.get("summary") or v.get("details", "") or "")
                        + (
                            f"\n\nScope: {dep.scope}. This dependency is not loaded at runtime "
                            "by consumers of this package; impact is limited to build/CI environments."
                            if is_dev
                            else ""
                        )
                    ),
                    remediation="Upgrade the dependency to a patched version.",
                    evidence=[
                        Evidence(
                            location=f"dependencies/{name}",
                            extra={"version": version, "scope": dep.scope},
                        )
                    ],
                    cwe=list({f"CWE-{w}" for w in _osv_cwes(v)}),
                    references=[r.get("url", "") for r in v.get("references", [])][:5],
                )
            )
    return findings, f"OSV: queried {len(queries)} deps, {len(findings)} vulns."


def _clean_version(v: str) -> str:
    # Turn "^1.2.3" / ">=1.2.0" / "~1.0" into a concrete-ish version string.
    import re as _re

    m = _re.search(r"\d+(?:\.\d+){1,3}", v)
    return m.group(0) if m else v


def _max_osv_severity(v: dict) -> Severity:
    # OSV "severity" entries carry CVSS vectors; parse CVSS score if present.
    best = 0.0
    for entry in v.get("severity", []) or []:
        score = entry.get("score", "")
        import re as _re

        m = _re.search(r"CVSS:\d+\.\d+/.+?(?:/|$)", score)
        _ = m  # just for readability
        # Try to grab a numeric score directly if present:
        m2 = _re.search(r"\b(\d+\.\d+)\b", score)
        if m2:
            try:
                best = max(best, float(m2.group(1)))
            except ValueError:
                pass
    if best >= 9.0:
        return Severity.CRITICAL
    if best >= 7.0:
        return Severity.HIGH
    if best >= 4.0:
        return Severity.MEDIUM
    if best > 0.0:
        return Severity.LOW
    # No CVSS score: use the "database_specific" severity if present; else Medium as default.
    db_sev = (v.get("database_specific") or {}).get("severity", "").upper()
    if db_sev == "CRITICAL":
        return Severity.CRITICAL
    if db_sev == "HIGH":
        return Severity.HIGH
    if db_sev == "LOW":
        return Severity.LOW
    return Severity.MEDIUM


def _osv_cwes(v: dict) -> list[str]:
    out = []
    for c in v.get("database_specific", {}).get("cwe_ids", []) or []:
        if isinstance(c, str) and c.startswith("CWE-"):
            out.append(c[4:])
    return out


# ---------- registry-signal checks ----------

# New-package window (days) below which a dep is considered "very young".
_YOUNG_PACKAGE_DAYS = 30
# Downloads-per-month threshold below which a dep is "rarely used".
_LOW_DOWNLOADS_MONTHLY = 100


async def _registry_signals(deps: list[DependencySummary]) -> tuple[list[Finding], str]:
    """Fetch age + download-count signals for each dep. One batch request per ecosystem."""
    findings: list[Finding] = []
    if not deps:
        return [], "Registry signals: no deps."
    async with httpx.AsyncClient(timeout=15) as client:
        for d in deps:
            try:
                if d.ecosystem == "npm":
                    sig = await _npm_signals(client, d.name)
                elif d.ecosystem == "pypi":
                    sig = await _pypi_signals(client, d.name)
                else:
                    continue
            except httpx.HTTPError:
                continue
            if sig is None:
                continue
            age_days, downloads_monthly, unpublished = sig
            if unpublished:
                findings.append(
                    Finding(
                        rule_id="MCP-SUP-008",
                        title=f"Dependency {d.name!r} no longer published",
                        category=Category.SUPPLY_CHAIN,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"{d.ecosystem} package {d.name!r} is no longer available in the "
                            "registry (yanked / unpublished / removed). Packages pulled for "
                            "malicious behavior sometimes reappear under a similar name."
                        ),
                        remediation="Replace with a maintained alternative and verify provenance.",
                        evidence=[Evidence(location=f"dependencies/{d.name}")],
                        references=[],
                    )
                )
                continue
            if age_days is not None and age_days < _YOUNG_PACKAGE_DAYS:
                findings.append(
                    Finding(
                        rule_id="MCP-SUP-009",
                        title=f"Very young dependency: {d.name!r} ({age_days}d old)",
                        category=Category.SUPPLY_CHAIN,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.SUSPECTED,
                        description=(
                            f"{d.ecosystem} package {d.name!r} was first published {age_days} days "
                            "ago. Fresh packages are disproportionately represented in supply-chain "
                            "incidents; at minimum, verify the maintainer."
                        ),
                        remediation=(
                            "Delay adoption of very new packages, or vendor + audit the source."
                        ),
                        evidence=[
                            Evidence(
                                location=f"dependencies/{d.name}",
                                extra={"first_release_age_days": age_days},
                            )
                        ],
                        references=[
                            "https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem",
                        ],
                    )
                )
            if downloads_monthly is not None and downloads_monthly < _LOW_DOWNLOADS_MONTHLY:
                findings.append(
                    Finding(
                        rule_id="MCP-SUP-010",
                        title=f"Rarely-used dependency: {d.name!r} (~{downloads_monthly}/mo)",
                        category=Category.SUPPLY_CHAIN,
                        severity=Severity.LOW,
                        confidence=Confidence.SUSPECTED,
                        description=(
                            f"{d.name!r} sees only ~{downloads_monthly} downloads/month. Obscure "
                            "packages accrue less scrutiny; small maintainer bases are more prone "
                            "to takeover."
                        ),
                        remediation="Prefer well-adopted alternatives where they exist.",
                        evidence=[
                            Evidence(
                                location=f"dependencies/{d.name}",
                                extra={"monthly_downloads": downloads_monthly},
                            )
                        ],
                    )
                )
    return findings, f"Registry signals: evaluated {len(deps)} deps."


async def _npm_signals(
    client: httpx.AsyncClient, name: str
) -> tuple[int | None, int | None, bool] | None:
    meta = await client.get(f"https://registry.npmjs.org/{name}")
    if meta.status_code == 404:
        return (None, None, True)
    if meta.status_code != 200:
        return None
    data = meta.json()
    unpublished = "unpublished" in (data.get("time") or {})
    age_days = _days_since(data.get("time", {}).get("created"))
    # downloads API is a separate endpoint.
    dl = await client.get(f"https://api.npmjs.org/downloads/point/last-month/{name}")
    monthly = None
    if dl.status_code == 200:
        try:
            monthly = int(dl.json().get("downloads", 0))
        except (ValueError, TypeError):
            monthly = None
    return (age_days, monthly, unpublished)


async def _pypi_signals(
    client: httpx.AsyncClient, name: str
) -> tuple[int | None, int | None, bool] | None:
    meta = await client.get(f"https://pypi.org/pypi/{name}/json")
    if meta.status_code == 404:
        return (None, None, True)
    if meta.status_code != 200:
        return None
    data = meta.json()
    releases = data.get("releases", {})
    # Earliest upload time across all releases = first-publish date.
    earliest = None
    for _, files in releases.items():
        for f in files:
            up = f.get("upload_time_iso_8601") or f.get("upload_time")
            if up:
                if earliest is None or up < earliest:
                    earliest = up
    age_days = _days_since(earliest)
    # PyPI has no official monthly-download API; skip.
    return (age_days, None, False)


def _days_since(iso_ts: str | None) -> int | None:
    if not iso_ts:
        return None
    from datetime import datetime, timezone

    try:
        if iso_ts.endswith("Z"):
            iso_ts = iso_ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


# ---------- phantom-repo check ----------


async def _phantom_repo_check(info: dict) -> tuple[list[Finding], str]:
    """Does the package's declared repository URL actually resolve?"""
    repo_url = None
    source_location = None

    pkg = info.get("package_json") or {}
    r = pkg.get("repository")
    if isinstance(r, dict):
        repo_url = r.get("url")
    elif isinstance(r, str):
        repo_url = r
    if repo_url:
        source_location = "package.json:repository"

    if repo_url is None:
        py_raw = info.get("pyproject_toml_raw", "") or ""
        import re as _re

        m = _re.search(
            r'(?:Homepage|Repository|Source)\s*=\s*["\'](https?://[^"\']+)["\']',
            py_raw,
            _re.IGNORECASE,
        )
        if m:
            repo_url = m.group(1)
            source_location = "pyproject.toml:urls"

    if not repo_url:
        return [], ""

    clean = (
        repo_url.replace("git+", "")
        .replace("git://", "https://")
        .replace(".git", "")
        .strip()
    )
    if not clean.startswith(("http://", "https://")):
        return [], ""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.head(clean)
            if resp.status_code >= 400:
                resp = await client.get(clean)
    except httpx.HTTPError:
        return [
            Finding(
                rule_id="MCP-PROV-002",
                title=f"Declared repository URL unreachable: {clean}",
                category=Category.PROVENANCE,
                severity=Severity.MEDIUM,
                confidence=Confidence.SUSPECTED,
                description=(
                    "The package manifest points at a repository URL that did not respond. "
                    "Phantom / unverifiable repository URLs are a provenance red flag — Wiz "
                    "found ~100 servers in a public registry linked to non-existent repos."
                ),
                remediation="Verify the project's real source; refuse if the vendor can't produce one.",
                evidence=[Evidence(location=source_location or "manifest", snippet=clean)],
                cwe=["CWE-1104"],
                references=[
                    "https://www.wiz.io/blog/mcp-security-research-briefing",
                ],
            )
        ], f"Phantom-repo check: {clean} unreachable."

    if resp.status_code >= 400:
        return [
            Finding(
                rule_id="MCP-PROV-002",
                title=f"Declared repository URL returns {resp.status_code}: {clean}",
                category=Category.PROVENANCE,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                description=(
                    f"GET {clean} returned {resp.status_code}. The repository advertised in the "
                    "manifest does not exist (or is private under a public-looking URL)."
                ),
                remediation="Resolve the correct source repository before trusting the package.",
                evidence=[Evidence(location=source_location or "manifest", snippet=clean)],
                cwe=["CWE-1104"],
                references=[
                    "https://www.wiz.io/blog/mcp-security-research-briefing",
                ],
            )
        ], f"Phantom-repo check: {clean} → {resp.status_code}."

    return [], f"Phantom-repo check: {clean} OK."
