"""Package mception as a Claude Desktop .mcpb bundle.

An .mcpb is a ZIP archive containing:
  - manifest.json at the root
  - the server entry point (here, the PyInstaller-bundled mception.exe)

The user installs it by double-clicking / dragging onto Claude Desktop. Claude
Desktop reads manifest.json, prompts for user_config values, substitutes them
into mcp_config.env, and launches the entry_point.

Usage:
    python packaging/build_bundle.py          # produces dist/mception.exe
    python packaging/build_mcpb.py            # wraps it as dist/mception.mcpb

Prerequisites: the PyInstaller bundle must exist (dist/mception.exe). If it
doesn't, this script refuses rather than silently producing a broken bundle.
"""

from __future__ import annotations

import json
import platform
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST = REPO_ROOT / "dist"
MANIFEST = REPO_ROOT / "packaging" / "manifest.json"


def main() -> int:
    if platform.system() != "Windows":
        print(
            "warning: this helper packages a Windows .exe. On non-Windows hosts "
            "the bundle it produces will only run on Windows targets.",
            file=sys.stderr,
        )

    exe = DIST / "mception.exe"
    if not exe.exists():
        print(
            f"error: {exe} not found. Run `python packaging/build_bundle.py` first.",
            file=sys.stderr,
        )
        return 2

    if not MANIFEST.exists():
        print(f"error: manifest not found at {MANIFEST}", file=sys.stderr)
        return 2

    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"error: manifest.json is not valid JSON: {e}", file=sys.stderr)
        return 2

    version = manifest.get("version", "dev")
    out = DIST / f"mception-{version}.mcpb"
    if out.exists():
        out.unlink()

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # Manifest must be at the archive root.
        z.write(MANIFEST, "manifest.json")
        # Binary referenced by server.entry_point.
        z.write(exe, "mception.exe")

    size_mb = out.stat().st_size / (1024 * 1024)
    print(f"[build_mcpb] wrote {out} ({size_mb:.1f} MB)")
    print("[build_mcpb] install: double-click the file, or drag it onto Claude Desktop.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
