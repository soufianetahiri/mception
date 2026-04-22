"""Surface classifier: what runtime does a source file actually execute in?

Ecosystem- and vendor-agnostic. The output is a coarse label that the SAST rules
use to calibrate severity/confidence when the meaning of a sink differs between
runtimes (e.g. ``eval`` in a plugin sandbox vs. ``eval`` in a long-lived Node
server: same AST node, very different blast radius).

Surfaces:
    "server"   – code runs as a Node/Python/Go/… process the MCP client connects
                 to. Classic sinks apply at full severity.
    "sandbox"  – code runs inside a host-managed runtime (browser/plugin/editor
                 extension/edge isolate). Node-flavoured sinks like
                 ``child_process.exec`` are unavailable; ``eval`` is the local
                 sandbox's *intended* extension mechanism, not RCE on the host.
    "build"    – bundler/test-runner config (vite/webpack config, rollup.config,
                 jest.config, wrangler.toml). Executed only at build/CI time.
    "unknown"  – no strong signal. Rules should treat as "server" to stay safe.

Detection is layered:

  1. **Manifest signal** – fast, high-precision. A file next to (or nested under
     a directory containing) a manifest whose shape declares a host-managed
     runtime is classified accordingly. Examples:
       - ``manifest.json`` with ``content_scripts`` or ``manifest_version`` →
         browser extension (sandbox)
       - ``manifest.json`` with ``editorType`` / ``main`` + ``ui`` keys →
         Figma-style plugin (sandbox)
       - ``package.json`` with ``engines.vscode`` or ``contributes`` → VS Code
         extension (sandbox)
       - ``wrangler.toml`` or ``wrangler.jsonc`` in the tree → Cloudflare Worker
         isolate (sandbox) for files under its ``main`` entry
       - ``deno.json`` / ``deno.jsonc`` with ``deploy`` config → Deno deploy
         isolate (sandbox)

  2. **Content signal** – when manifests have been stripped (e.g. npm tarball
     doesn't include plugin manifests), fall back to heavy usage of a
     host-managed global namespace. Vendor-agnostic by design: the classifier
     doesn't know or care *which* host; it only counts distinct API surface
     hits. Any global namespace whose member access dominates a file is a
     strong sandbox signal (``figma.``, ``chrome.``, ``browser.``, ``vscode.``,
     ``Deno.``, ``WebAssembly.``). We don't enumerate vendors exhaustively —
     just require a minimum density and bare-global pattern.

No file content is persisted; the classifier is called per-file during SAST.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

Surface = Literal["server", "sandbox", "build", "unknown"]


# Build-tool / config files: executed only at build/test time. Keyed by filename.
_BUILD_FILENAMES: set[str] = {
    "vite.config.js",
    "vite.config.ts",
    "vite.config.mjs",
    "webpack.config.js",
    "webpack.config.ts",
    "rollup.config.js",
    "rollup.config.ts",
    "esbuild.config.js",
    "jest.config.js",
    "jest.config.ts",
    "vitest.config.ts",
    "vitest.config.js",
    "babel.config.js",
    "tsup.config.ts",
    "wrangler.toml",
    "wrangler.jsonc",
    "wrangler.json",
}

# Regex matching dominant host-global member access. A file that references
# ``<global>.method(...)`` or ``<global>.property`` repeatedly is almost
# certainly executing in that host's sandbox. We don't hardcode which global —
# the pattern captures any identifier, and the threshold filters noise.
_HOST_GLOBAL_RX = re.compile(
    r"\b(figma|chrome|browser|vscode|Deno|WebAssembly|browserAction|runtime)"
    r"\s*\.\s*[A-Za-z_$][\w$]*",
)
# Density threshold: this many distinct host-global accesses in one file makes
# it a sandbox surface with high confidence. Set high enough that a stray
# ``chrome.exe`` path string in a log message doesn't trigger it.
_HOST_GLOBAL_DENSITY = 8


def _read_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


@lru_cache(maxsize=64)
def _workdir_manifest_surfaces(workdir: Path) -> tuple[tuple[str, Surface], ...]:
    """Scan *workdir* for manifests that declare host-managed surfaces.

    Returns a tuple of ``(path_prefix, surface)`` pairs. A source file whose
    path starts with *path_prefix* inherits *surface* unless an inner manifest
    overrides it.
    """
    out: list[tuple[str, Surface]] = []

    # package.json at any depth can declare VS Code extensions.
    for pj in workdir.rglob("package.json"):
        data = _read_json(pj)
        if not isinstance(data, dict):
            continue
        engines = data.get("engines") or {}
        if "vscode" in engines or "contributes" in data:
            out.append((str(pj.parent), "sandbox"))

    # Browser extension / MV3 style manifest.
    for mf in workdir.rglob("manifest.json"):
        data = _read_json(mf)
        if not isinstance(data, dict):
            continue
        if (
            "content_scripts" in data
            or "manifest_version" in data
            or "background" in data
            or data.get("editorType")  # Figma-style
            or (data.get("main") and data.get("ui"))  # Figma plugin shape
            or data.get("api")  # Figma plugin API declaration
        ):
            out.append((str(mf.parent), "sandbox"))

    # Cloudflare Workers: a wrangler config anywhere implies an isolate target
    # for the code under its dir.
    for wr in list(workdir.rglob("wrangler.toml")) + list(workdir.rglob("wrangler.jsonc")):
        out.append((str(wr.parent), "sandbox"))

    # Deno runtime: deno.json / deno.jsonc signals deno deploy if it has a task
    # named "deploy" or a "deploy" section. Bare deno.json is still server.
    for dj in list(workdir.rglob("deno.json")) + list(workdir.rglob("deno.jsonc")):
        data = _read_json(dj)
        if isinstance(data, dict) and ("deploy" in data or "deploy" in (data.get("tasks") or {})):
            out.append((str(dj.parent), "sandbox"))

    # Longest prefix wins when a source file is nested under multiple.
    out.sort(key=lambda t: len(t[0]), reverse=True)
    return tuple(out)


def classify_surface(path: Path, src: str, workdir: Path) -> Surface:
    """Classify one source file's execution surface. See module docstring.

    *path* should be inside *workdir*; otherwise manifest inheritance falls
    back to content-only detection.
    """
    # 1) Build-tool config — filename-based.
    if path.name in _BUILD_FILENAMES:
        return "build"

    # 2) Manifest-inherited surface.
    try:
        path_str = str(path)
        for prefix, surface in _workdir_manifest_surfaces(workdir):
            if path_str.startswith(prefix):
                return surface
    except (OSError, ValueError):
        pass

    # 3) Content signal: dense use of a host-managed global.
    hits = set()
    for m in _HOST_GLOBAL_RX.finditer(src):
        hits.add(m.group(0))
        if len(hits) >= _HOST_GLOBAL_DENSITY:
            return "sandbox"

    return "unknown"
