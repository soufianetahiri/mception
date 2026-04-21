"""Build a portable single-file mception executable with PyInstaller.

Usage:
    python packaging/build_bundle.py

Produces `dist/mception` (or `dist\\mception.exe` on Windows). No Python
required on the target machine — the binary ships its own interpreter.

Prerequisites:
    pip install -e ".[bundle]"
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "packaging" / "mception.spec"
DIST = REPO_ROOT / "dist"
BUILD = REPO_ROOT / "build"


def main() -> int:
    if not SPEC.exists():
        print(f"error: spec file not found at {SPEC}", file=sys.stderr)
        return 2

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print(
            'error: PyInstaller is not installed. Run `pip install -e ".[bundle]"` first.',
            file=sys.stderr,
        )
        return 2

    for p in (DIST, BUILD):
        if p.exists():
            shutil.rmtree(p)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(SPEC),
        "--clean",
        "--noconfirm",
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD),
    ]
    print(f"[build_bundle] running: {' '.join(cmd)}")
    rc = subprocess.call(cmd, cwd=REPO_ROOT)
    if rc != 0:
        return rc

    artifact = DIST / ("mception.exe" if platform.system() == "Windows" else "mception")
    if not artifact.exists():
        print(f"error: expected artifact not found at {artifact}", file=sys.stderr)
        return 1

    size_mb = artifact.stat().st_size / (1024 * 1024)
    print(f"[build_bundle] success: {artifact} ({size_mb:.1f} MB)")
    print("[build_bundle] smoke-test the bundle with:")
    print(f'    "{artifact}" --help')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
