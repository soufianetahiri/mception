"""Supply-chain rules: manifest parsing, postinstall detection, typosquat, obfuscation."""

from __future__ import annotations

import ast
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..findings import Category, Confidence, Evidence, Finding, Severity


# Small built-in allowlist of well-known packages to check typosquat distance against.
# Kept intentionally short; expand as needed. These are names we'd expect to see as
# legitimate dependencies of an MCP server.
_TYPOSQUAT_REFERENCE_NPM = {
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/inspector",
    "fastmcp",
    "zod",
    "express",
    "axios",
    "dotenv",
    "typescript",
    "node-fetch",
    "ws",
    "chalk",
    "commander",
    "yaml",
    "js-yaml",
    "lodash",
    "underscore",
    "react",
    "next",
    "cors",
    "helmet",
    "jsonwebtoken",
    "bcrypt",
    "mongodb",
    "mongoose",
    "pg",
    "redis",
    "socket.io",
    "esbuild",
    "vite",
    "eslint",
    "prettier",
    "tsx",
    "undici",
    "winston",
    "pino",
}
_TYPOSQUAT_REFERENCE_GO = {
    "github.com/modelcontextprotocol/go-sdk",
    "github.com/mark3labs/mcp-go",
    "github.com/metoro-io/mcp-golang",
    "github.com/spf13/cobra",
    "github.com/spf13/viper",
    "github.com/gorilla/mux",
    "github.com/gin-gonic/gin",
    "github.com/labstack/echo",
    "github.com/sirupsen/logrus",
    "github.com/stretchr/testify",
    "github.com/google/uuid",
    "github.com/golang-jwt/jwt",
    "github.com/jackc/pgx",
    "github.com/lib/pq",
    "gopkg.in/yaml.v3",
    "golang.org/x/crypto",
    "golang.org/x/net",
    "golang.org/x/sync",
}
_TYPOSQUAT_REFERENCE_CRATES = {
    "rmcp",
    "mcp-sdk",
    "tokio",
    "serde",
    "serde_json",
    "reqwest",
    "hyper",
    "axum",
    "actix-web",
    "clap",
    "anyhow",
    "thiserror",
    "tracing",
    "uuid",
    "chrono",
    "regex",
    "rand",
    "sha2",
    "base64",
}
_TYPOSQUAT_REFERENCE_PYPI = {
    "mcp",
    "anthropic",
    "pydantic",
    "httpx",
    "requests",
    "fastapi",
    "uvicorn",
    "starlette",
    "aiohttp",
    "typer",
    "click",
    "sqlalchemy",
    "pyyaml",
    "cryptography",
    "numpy",
    "pandas",
    "openai",
    "scikit-learn",
    "scipy",
    "matplotlib",
    "boto3",
    "botocore",
    "urllib3",
    "certifi",
    "charset-normalizer",
    "idna",
    "setuptools",
    "wheel",
    "pip",
    "python-dotenv",
    "jinja2",
    "markupsafe",
    "rich",
    "tqdm",
    "pytest",
    "black",
    "ruff",
    "mypy",
    "pillow",
    "pyjwt",
}


@dataclass
class DependencySummary:
    name: str
    version: str | None
    ecosystem: str  # "npm" | "pypi" | "go" | "crates"
    spec_raw: str | None = None  # original version spec incl. operator ("^1.2.3", "==2.0")


# ---------- manifest parsing ----------


def parse_manifests(workdir: Path) -> tuple[list[DependencySummary], dict]:
    """Return (deps, misc_info). misc_info contains raw manifest dicts for other rules."""
    deps: list[DependencySummary] = []
    info: dict = {}
    pkg = workdir / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            info["package_json"] = data
            for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, spec in (data.get(sec) or {}).items():
                    spec_s = str(spec)
                    # For npm, "version" (clean) and "spec_raw" are the same string.
                    deps.append(
                        DependencySummary(
                            name=name,
                            version=spec_s,
                            spec_raw=spec_s,
                            ecosystem="npm",
                        )
                    )
        except json.JSONDecodeError:
            pass
    py_req = workdir / "requirements.txt"
    if py_req.exists():
        info["requirements_txt"] = py_req.read_text(encoding="utf-8", errors="replace")
        for line in py_req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Capture operator + version as a unit so we can tell pinned from ranges.
            m = re.match(
                r"^([A-Za-z0-9_.\-]+)\s*((?:[<>=!~]=?\s*[A-Za-z0-9_.\-]+)?)",
                line,
            )
            if m:
                spec_raw = (m.group(2) or "").strip() or None
                version = re.search(r"[A-Za-z0-9_.\-]+$", spec_raw).group(0) if spec_raw else None
                deps.append(
                    DependencySummary(
                        name=m.group(1),
                        version=version,
                        spec_raw=spec_raw,
                        ecosystem="pypi",
                    )
                )
    pyproj = workdir / "pyproject.toml"
    if pyproj.exists():
        info["pyproject_toml_raw"] = pyproj.read_text(encoding="utf-8", errors="replace")
        # Capture full spec string (incl. operator) from quoted dep entries.
        for m in re.finditer(
            r'["\']([A-Za-z0-9_.\-]+)\s*((?:[<>=!~]=?\s*[A-Za-z0-9_.\-]+)?)["\']',
            info["pyproject_toml_raw"],
        ):
            spec_raw = (m.group(2) or "").strip() or None
            version = re.search(r"[A-Za-z0-9_.\-]+$", spec_raw).group(0) if spec_raw else None
            deps.append(
                DependencySummary(
                    name=m.group(1),
                    version=version,
                    spec_raw=spec_raw,
                    ecosystem="pypi",
                )
            )

    # Go module: go.mod
    gomod = workdir / "go.mod"
    if gomod.exists():
        info["go_mod_raw"] = gomod.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(
            r"^\s*([a-zA-Z0-9._/\-]+(?:\.[a-zA-Z0-9._/\-]+)+)\s+v([0-9][\w.\-+]+)",
            info["go_mod_raw"],
            re.MULTILINE,
        ):
            deps.append(
                DependencySummary(
                    name=m.group(1),
                    version=m.group(2),
                    spec_raw=f"v{m.group(2)}",
                    ecosystem="go",
                )
            )

    # Rust: Cargo.toml
    cargo = workdir / "Cargo.toml"
    if cargo.exists():
        info["cargo_toml_raw"] = cargo.read_text(encoding="utf-8", errors="replace")
        # Top-level [dependencies] + [dev-dependencies] — simple tomls only.
        raw = info["cargo_toml_raw"]
        for block_name in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
            idx = raw.find(block_name)
            if idx < 0:
                continue
            end = raw.find("\n[", idx + 1)
            block = raw[idx:end] if end != -1 else raw[idx:]
            # 1) `name = "1.2.3"`
            for m in re.finditer(
                r'^\s*([a-zA-Z0-9_\-]+)\s*=\s*"([^"]+)"',
                block,
                re.MULTILINE,
            ):
                deps.append(
                    DependencySummary(
                        name=m.group(1),
                        version=m.group(2),
                        spec_raw=m.group(2),
                        ecosystem="crates",
                    )
                )
            # 2) `name = { version = "1.2.3", ... }`
            for m in re.finditer(
                r'^\s*([a-zA-Z0-9_\-]+)\s*=\s*\{[^}]*?\bversion\s*=\s*"([^"]+)"',
                block,
                re.MULTILINE | re.DOTALL,
            ):
                deps.append(
                    DependencySummary(
                        name=m.group(1),
                        version=m.group(2),
                        spec_raw=m.group(2),
                        ecosystem="crates",
                    )
                )

    return deps, info


# ---------- rules ----------


def rule_postinstall_scripts(workdir: Path, info: dict) -> Iterable[Finding]:
    data = info.get("package_json")
    if not data:
        return []
    scripts = data.get("scripts") or {}
    dangerous = {
        k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall")
    }
    if not dangerous:
        return []
    return [
        Finding(
            rule_id="MCP-SUP-001",
            title="package.json defines install-time scripts",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "Scripts in "
                + ", ".join(sorted(dangerous))
                + " run arbitrary code on `npm install` before the user has reviewed anything. "
                "Canonical vector for supply-chain compromise."
            ),
            remediation=(
                "Remove install-time scripts; perform setup in an explicit CLI command the user "
                "can audit. If unavoidable, pin a lockfile + integrity hash and review the script."
            ),
            evidence=[
                Evidence(
                    location=str((workdir / "package.json")),
                    snippet=json.dumps(dangerous, indent=2)[:400],
                )
            ],
            cwe=["CWE-506"],
            owasp_mcp="MCP04:2025",
            references=[
                "https://www.helpnetsecurity.com/2026/02/24/npm-worm-sandworm-mode-supply-cain-attack/",
                "https://securitylabs.datadoghq.com/articles/mut-8964-an-npm-and-pypi-malicious-campaign-targeting-windows-users/",
            ],
        )
    ]


def rule_setuppy_sideeffects(workdir: Path) -> Iterable[Finding]:
    setup = workdir / "setup.py"
    if not setup.exists():
        return []
    try:
        src = setup.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except SyntaxError:
        return []
    risky: list[str] = []
    for node in tree.body:  # only top-level statements
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            chain = _callee(node.value.func)
            if chain in ("os.system", "subprocess.run", "subprocess.Popen", "subprocess.call"):
                risky.append(chain)
        if isinstance(node, ast.Call):
            chain = _callee(node.func)
            if chain in ("os.system", "subprocess.run", "subprocess.Popen", "subprocess.call"):
                risky.append(chain)
        if isinstance(node, (ast.If, ast.For, ast.Try)):
            # Custom install command classes also trigger; best-effort flag top-level conditionals.
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    chain = _callee(sub.func)
                    if chain and chain.split(".")[-1] in ("system", "Popen", "run", "call"):
                        risky.append(chain or "<shell>")
    if not risky:
        return []
    return [
        Finding(
            rule_id="MCP-SUP-004",
            title="setup.py runs subprocess at import time",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            description=(
                "Top-level statements in setup.py invoke shell/subprocess APIs: "
                + ", ".join(sorted(set(risky)))
                + ". These execute during `pip install` before any review."
            ),
            remediation=(
                "Move setup-time commands to an explicit CLI subcommand the user invokes. "
                "Keep setup.py declarative."
            ),
            evidence=[Evidence(location=str(setup), snippet=src[:300])],
            cwe=["CWE-506"],
            owasp_mcp="MCP04:2025",
            references=[
                "https://semgrep.dev/blog/2026/the-teampcp-credential-infostealer-chain-attack-reaches-pythons-litellm/",
            ],
        )
    ]


def _callee(node: ast.expr | None) -> str | None:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def rule_typosquat(deps: list[DependencySummary]) -> Iterable[Finding]:
    """Flag dep names that are edit-distance 1 or 2 from a known-good popular package name."""
    findings: list[Finding] = []
    ref_by_ecosystem = {
        "npm": _TYPOSQUAT_REFERENCE_NPM,
        "pypi": _TYPOSQUAT_REFERENCE_PYPI,
        "go": _TYPOSQUAT_REFERENCE_GO,
        "crates": _TYPOSQUAT_REFERENCE_CRATES,
    }
    for dep in deps:
        ref = ref_by_ecosystem.get(dep.ecosystem, set())
        if not ref or dep.name in ref:
            continue
        best_match = None
        best_dist = 999
        for candidate in ref:
            d = _levenshtein(dep.name.lower(), candidate.lower())
            if d < best_dist:
                best_dist = d
                best_match = candidate
        if best_match and 1 <= best_dist <= 2 and len(dep.name) >= 4:
            findings.append(
                Finding(
                    rule_id="MCP-SUP-002",
                    title=f"Dependency {dep.name!r} resembles {best_match!r}",
                    category=Category.SUPPLY_CHAIN,
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        f"{dep.ecosystem} dependency {dep.name!r} is edit-distance {best_dist} from "
                        f"popular package {best_match!r}. Possible typosquat."
                    ),
                    remediation=(
                        f"Confirm {dep.name!r} is genuinely what you want. If you meant "
                        f"{best_match!r}, replace it."
                    ),
                    evidence=[Evidence(location=f"dependencies/{dep.name}")],
                    cwe=["CWE-1357"],
                    owasp_mcp="MCP04:2025",
                    references=[
                        "https://nesbitt.io/2025/12/17/typosquatting-in-package-managers.html",
                    ],
                )
            )
    return findings


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def rule_obfuscation(workdir: Path) -> Iterable[Finding]:
    """Flag source files that look obfuscated (packed strings, huge one-liners)."""
    findings: list[Finding] = []
    for p in workdir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in (".py", ".js", ".mjs", ".cjs", ".ts"):
            continue
        if any(s in p.parts for s in ("node_modules", ".git", "__pycache__", "dist", "build")):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(src) > 2_000_000:
            continue
        # Heuristics.
        lines = src.splitlines() or [""]
        long_lines = [ln for ln in lines if len(ln) > 800]
        # Entropy of the longest line (Shannon in bits/char).
        entropy = _entropy(max(lines, key=len)) if lines else 0.0
        base64ish = re.search(r"[A-Za-z0-9+/]{200,}={0,2}", src)
        packed_eval = re.search(r"\beval\s*\(\s*(?:atob|Buffer\.from|unescape)\s*\(", src)
        if long_lines and entropy > 4.8:
            findings.append(
                Finding(
                    rule_id="MCP-SUP-003",
                    title=f"Obfuscated code in {p.name}",
                    category=Category.SUPPLY_CHAIN,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        f"File contains very long lines with high Shannon entropy "
                        f"({entropy:.2f} bits/char). Typical of packed/minified malware deliveries."
                    ),
                    remediation=(
                        "Open the file and verify it's legitimate generated output. If not, remove it."
                    ),
                    evidence=[Evidence(location=str(p), snippet=max(lines, key=len)[:200])],
                    cwe=["CWE-506"],
                )
            )
        if packed_eval or base64ish:
            findings.append(
                Finding(
                    rule_id="MCP-SUP-003",
                    title=f"Runtime-decoded code in {p.name}",
                    category=Category.SUPPLY_CHAIN,
                    severity=Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    description=(
                        "File contains a pattern of runtime decoding (base64 blob, "
                        "eval(atob(...)), Buffer.from) which is near-universal in malicious packages."
                    ),
                    remediation="Inspect the decoded payload. If unexpected, refuse the package.",
                    evidence=[Evidence(location=str(p))],
                    cwe=["CWE-506"],
                )
            )
    return findings


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------- new rules (extension) ----------


# npm ranges using ^/~ or a git/file spec → not reproducible.
_NPM_UNPINNED_RX = re.compile(r"^(?:[\^~>]|>=|\*|latest$|file:|git\+|github:|http)")


def rule_unpinned_versions(deps: list[DependencySummary], info: dict) -> Iterable[Finding]:
    """Flag dependency specs that aren't pinned to an exact version."""
    bad: list[tuple[str, str]] = []
    for d in deps:
        spec = (d.spec_raw or d.version or "").strip()
        if not spec:
            continue
        if d.ecosystem == "npm":
            # "^1.2.3" / "~1.0" / ">=1.0.0" / "latest" / "git+…" / "file:…" are all floating.
            if _NPM_UNPINNED_RX.match(spec):
                bad.append((d.name, spec))
        else:  # pypi
            # An exact pin in pip specifiers is "==1.2.3". Anything else floats.
            if not spec.startswith("=="):
                bad.append((d.name, spec))
    if not bad:
        return []
    sample = ", ".join(f"{n}@{v}" for n, v in bad[:6])
    more = f" (+{len(bad) - 6} more)" if len(bad) > 6 else ""
    return [
        Finding(
            rule_id="MCP-SUP-005",
            title="Floating dependency ranges reduce integrity",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            description=(
                f"{len(bad)} dependency spec(s) are not pinned to an exact version: "
                f"{sample}{more}. A compromised registry can ship a new patch version "
                "under a range spec and every install picks it up."
            ),
            remediation=(
                "Pin exact versions (`1.2.3` in npm, `==1.2.3` in pip) and commit a "
                "lockfile with integrity hashes."
            ),
            evidence=[Evidence(location="dependencies", extra={"unpinned": bad[:40]})],
            cwe=["CWE-494"],
            owasp_mcp="MCP04:2025",
            references=[
                "https://owasp.org/www-project-mcp-top-10/2025/MCP04-2025%E2%80%93Software-Supply-Chain-Attacks&Dependency-Tampering",
            ],
        )
    ]


def rule_no_lockfile(workdir: Path, deps: list[DependencySummary]) -> Iterable[Finding]:
    """If a manifest declares deps but no lockfile is present, integrity is not guaranteed."""
    has_npm_deps = any(d.ecosystem == "npm" for d in deps)
    has_py_deps = any(d.ecosystem == "pypi" for d in deps)
    findings: list[Finding] = []

    if has_npm_deps:
        lockfiles = [
            workdir / "package-lock.json",
            workdir / "yarn.lock",
            workdir / "pnpm-lock.yaml",
            workdir / "bun.lockb",
            workdir / "bun.lock",
        ]
        if not any(lf.exists() for lf in lockfiles):
            findings.append(_lockfile_finding("npm", str(workdir / "package.json")))

    if has_py_deps:
        lockfiles = [
            workdir / "uv.lock",
            workdir / "poetry.lock",
            workdir / "Pipfile.lock",
            workdir / "requirements.lock",
            workdir / "pylock.toml",
        ]
        if not any(lf.exists() for lf in lockfiles):
            # Do not flag pure requirements.txt-with-hashes: detect --hash lines.
            req = workdir / "requirements.txt"
            if req.exists() and "--hash=" in req.read_text(encoding="utf-8", errors="replace"):
                pass
            else:
                findings.append(_lockfile_finding("python", str(workdir)))

    return findings


def _lockfile_finding(ecosystem: str, location: str) -> Finding:
    return Finding(
        rule_id="MCP-SUP-006",
        title=f"Missing {ecosystem} lockfile / integrity hashes",
        category=Category.SUPPLY_CHAIN,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description=(
            f"Dependencies are declared but no {ecosystem} lockfile (or hashed pinfile) is present. "
            "Every fresh install resolves against live registry metadata — a compromised mirror "
            "or maintainer can ship a malicious version undetected."
        ),
        remediation=(
            f"Commit a lockfile (`{'package-lock.json' if ecosystem == 'npm' else 'uv.lock / poetry.lock'}`), "
            "or use `pip install --require-hashes` with hashed requirements."
        ),
        evidence=[Evidence(location=location)],
        cwe=["CWE-494"],
        owasp_mcp="MCP04:2025",
        references=[
            "https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/",
        ],
    )


_SUSPICIOUS_BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".node", ".scr", ".msi"}
_BENIGN_FILES = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"}
_BENIGN_DIRS = {"node_modules", ".git", "__pycache__", "dist", "build", "target", "bin", "venv", ".venv"}


def rule_suspicious_binaries(workdir: Path) -> Iterable[Finding]:
    """Flag unexpected binary artifacts that shouldn't be in a source distribution."""
    hits: list[tuple[Path, int]] = []
    for p in workdir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _BENIGN_DIRS for part in p.parts):
            continue
        suf = p.suffix.lower()
        if suf in _SUSPICIOUS_BINARY_EXTS:
            try:
                hits.append((p, p.stat().st_size))
            except OSError:
                continue
    if not hits:
        return []
    # Cap evidence to the 5 largest.
    hits.sort(key=lambda x: -x[1])
    shown = hits[:5]
    return [
        Finding(
            rule_id="MCP-SUP-007",
            title=f"Unexpected binary artifact(s) shipped in source",
            category=Category.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            description=(
                f"Package contains {len(hits)} binary file(s) with extensions commonly used for "
                "executables or shared libraries. MCP servers are overwhelmingly source-only; "
                "prebuilt binaries are a classic way to ship malware."
            ),
            remediation=(
                "Remove the binary from the source tree. If it's genuinely required, document "
                "its provenance and verify its hash against a reproducible build."
            ),
            evidence=[
                Evidence(
                    location=str(p),
                    extra={"bytes": size},
                )
                for p, size in shown
            ],
            cwe=["CWE-506"],
            owasp_mcp="MCP04:2025",
        )
    ]


def rule_missing_license(info: dict, workdir: Path) -> Iterable[Finding]:
    """Flag packages that publish without a license — provenance red flag."""
    has_npm = "package_json" in info
    has_py = "pyproject_toml_raw" in info
    if not (has_npm or has_py):
        return []
    npm_license = (info.get("package_json") or {}).get("license")
    py_raw = info.get("pyproject_toml_raw", "")
    py_license_mentioned = bool(re.search(r"\blicense\s*=", py_raw, re.IGNORECASE))
    has_license_file = any(
        (workdir / name).exists() for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING")
    )
    if has_npm and not npm_license and not has_license_file:
        return [_missing_license(str(workdir / "package.json"))]
    if has_py and not py_license_mentioned and not has_license_file:
        return [_missing_license(str(workdir / "pyproject.toml"))]
    return []


def _missing_license(location: str) -> Finding:
    return Finding(
        rule_id="MCP-PROV-001",
        title="Package ships without a license",
        category=Category.PROVENANCE,
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        description=(
            "No license field in the manifest and no LICENSE/COPYING file in the source tree. "
            "This is an unusual provenance signal for a published package: review the source's "
            "origin before accepting."
        ),
        remediation=(
            "Either require the package to declare a license or get written permission from "
            "the author before distributing/running."
        ),
        evidence=[Evidence(location=location)],
        cwe=["CWE-1104"],
        references=[
            "https://www.wiz.io/blog/mcp-security-research-briefing",
        ],
    )
