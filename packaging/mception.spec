# PyInstaller spec for mception.
# Produces a single-file executable that bundles Python + all runtime deps.
#
# Build locally:   python -m PyInstaller packaging/mception.spec --clean
# Or via helper:   python packaging/build_bundle.py

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

datas = []
binaries = []
hiddenimports = []

# Skip submodules that pull in optional extras we don't ship
# (e.g. `mcp.cli` needs `typer`, which is only installed by `mcp[cli]`).
_SKIP_PREFIXES = ("mcp.cli",)


def _keep(name: str) -> bool:
    return not any(name == p or name.startswith(p + ".") for p in _SKIP_PREFIXES)


# MCP SDK uses lazy re-exports and dynamic dispatch; sweep the full package
# but skip optional subpackages.
for pkg in ("mcp", "pydantic", "pydantic_core", "rich", "anyio", "httpx"):
    datas += collect_data_files(pkg)
    binaries += collect_dynamic_libs(pkg)
    hiddenimports += collect_submodules(pkg, filter=_keep)

# mception itself — make sure every rule / engine submodule is included even if
# only referenced via registry lookups.
hiddenimports += collect_submodules("mception")


a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # SAST backends are optional extras and heavy; users who want them
        # install the regular wheel. Keep the portable bundle lean.
        "bandit",
        "semgrep",
        "cyclonedx_bom",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="mception",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,            # stdio MCP transport needs a console app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
