"""Target fetcher — resolves a target reference to a local workdir + kind.

Scopes supported in this phase:

  - local:/path or absolute path → use as-is (read-only)
  - git+https://host/org/repo[.git][@ref]  → `git clone` + optional checkout
  - pypi:<name>[==version] → download sdist from PyPI JSON API, extract
  - npm:<name>[@version]   → download tarball from npm registry JSON API, extract
  - docker:<image>         → NOT fetched; flagged inconclusive for static analysis
    (docker image scanning is out of scope for Phase 1)

Everything lands under a unique tempdir. Never executes any install scripts.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from ..config import settings


@dataclass
class FetchResult:
    workdir: Path
    kind: str  # normalized: "local" | "git" | "pypi" | "npm" | "docker"
    cleanup: bool  # True if caller should rmtree workdir after audit
    notes: list[str]


class FetchError(RuntimeError):
    pass


_NPM_REF = re.compile(r"^npm:(?P<name>@?[\w\-./]+)(?:@(?P<version>[\w\-.]+))?$")
_PYPI_REF = re.compile(r"^pypi:(?P<name>[\w\-.]+)(?:==(?P<version>[\w\-.]+))?$")
_GIT_REF = re.compile(r"^git\+(?P<url>https?://[^\s@]+?)(?:@(?P<ref>[^\s]+))?$")


def detect_kind(target: str) -> str:
    if target.startswith("npm:"):
        return "npm"
    if target.startswith("pypi:"):
        return "pypi"
    if target.startswith("git+"):
        return "git"
    if target.startswith("docker:"):
        return "docker"
    if target.startswith("local:") or Path(target).exists():
        return "local"
    return "unknown"


async def fetch(target: str, kind: str | None = None) -> FetchResult:
    """Resolve a target ref to a local workdir."""
    k = kind or detect_kind(target)
    if k == "local":
        p = Path(target.removeprefix("local:"))
        if not p.exists():
            raise FetchError(f"local path does not exist: {p}")
        return FetchResult(workdir=p, kind="local", cleanup=False, notes=[f"local path {p}"])
    if k == "docker":
        raise FetchError("docker targets not supported in Phase 1 (static)")
    if settings.offline_mode and k in ("git", "pypi", "npm"):
        raise FetchError(f"offline mode: cannot fetch {k} target")

    tmp = Path(tempfile.mkdtemp(prefix="mception-"))
    try:
        if k == "git":
            m = _GIT_REF.match(target)
            if not m:
                raise FetchError(f"invalid git ref: {target}")
            url, ref = m.group("url"), m.group("ref")
            _run_git(["clone", "--depth", "1", url, str(tmp)])
            if ref:
                _run_git(["fetch", "--depth", "1", "origin", ref], cwd=tmp)
                _run_git(["checkout", "FETCH_HEAD"], cwd=tmp)
            return FetchResult(
                workdir=tmp, kind="git", cleanup=True, notes=[f"cloned {url}" + (f"@{ref}" if ref else "")]
            )
        if k == "pypi":
            m = _PYPI_REF.match(target)
            if not m:
                raise FetchError(f"invalid pypi ref: {target}")
            name, version = m.group("name"), m.group("version")
            return await _fetch_pypi(name, version, tmp)
        if k == "npm":
            m = _NPM_REF.match(target)
            if not m:
                raise FetchError(f"invalid npm ref: {target}")
            name, version = m.group("name"), m.group("version")
            return await _fetch_npm(name, version, tmp)
        raise FetchError(f"unknown target kind: {k}")
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _run_git(args: list[str], cwd: Path | None = None) -> None:
    # Git is a widely-deployed binary we rely on — not user-controlled input in argv.
    try:
        subprocess.run(  # noqa: S603
            ["git", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            timeout=120,
        )
    except FileNotFoundError as e:
        raise FetchError("git executable not found in PATH") from e
    except subprocess.CalledProcessError as e:
        raise FetchError(f"git {args[0]} failed: {e.stderr.decode('utf-8', 'replace')[:300]}") from e


async def _fetch_pypi(name: str, version: str | None, dest: Path) -> FetchResult:
    async with httpx.AsyncClient(timeout=30) as client:
        meta_url = f"https://pypi.org/pypi/{name}/json"
        r = await client.get(meta_url)
        r.raise_for_status()
        meta = r.json()
        v = version or meta["info"]["version"]
        files = meta.get("releases", {}).get(v, [])
        if not files:
            raise FetchError(f"no files for {name}=={v}")
        # Prefer sdist (tar.gz / zip), else wheel.
        sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
        chosen = sdist or files[0]
        url = chosen["url"]
        blob = (await client.get(url, follow_redirects=True)).content
    if url.endswith(".tar.gz") or url.endswith(".tgz"):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            _safe_extract_tar(tf, dest)
    elif url.endswith(".zip") or url.endswith(".whl"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            _safe_extract_zip(zf, dest)
    else:
        raise FetchError(f"unsupported pypi artifact: {url}")
    return FetchResult(workdir=dest, kind="pypi", cleanup=True, notes=[f"pypi {name}=={v}", url])


async def _fetch_npm(name: str, version: str | None, dest: Path) -> FetchResult:
    async with httpx.AsyncClient(timeout=30) as client:
        meta_url = f"https://registry.npmjs.org/{name}"
        r = await client.get(meta_url)
        r.raise_for_status()
        meta = r.json()
        v = version or meta.get("dist-tags", {}).get("latest")
        if not v or v not in meta.get("versions", {}):
            raise FetchError(f"npm: no version resolvable for {name}")
        tarball_url = meta["versions"][v]["dist"]["tarball"]
        blob = (await client.get(tarball_url, follow_redirects=True)).content
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        _safe_extract_tar(tf, dest)
    # npm tarballs extract under a top-level "package/" dir; flatten to dest root if so.
    pkg_sub = dest / "package"
    if pkg_sub.is_dir():
        for p in pkg_sub.iterdir():
            shutil.move(str(p), str(dest / p.name))
        pkg_sub.rmdir()
    return FetchResult(
        workdir=dest, kind="npm", cleanup=True, notes=[f"npm {name}@{v}", tarball_url]
    )


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    """Tar extraction with zip-slip defense."""
    dest_resolved = dest.resolve()
    for m in tf.getmembers():
        # Reject absolute paths and path traversal.
        candidate = (dest / m.name).resolve()
        try:
            candidate.relative_to(dest_resolved)
        except ValueError as e:
            raise FetchError(f"tar traversal attempt: {m.name}") from e
        if m.issym() or m.islnk():
            # Skip symlinks entirely — they can still point outside after extraction.
            continue
    tf.extractall(dest, filter="data")


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for name in zf.namelist():
        candidate = (dest / name).resolve()
        try:
            candidate.relative_to(dest_resolved)
        except ValueError as e:
            raise FetchError(f"zip traversal attempt: {name}") from e
    zf.extractall(dest)
