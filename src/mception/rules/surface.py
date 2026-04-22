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

Python and Go additions
-----------------------

Beyond the original JS / TS / Node / browser-extension manifests, the
classifier also recognizes:

  * **Python sandbox signals**
      - ``jupyter_notebook_config.py`` anywhere in the tree marks files under
        its directory as ``sandbox`` — the notebook kernel is a host-managed
        Python runtime where ``subprocess`` is frequently unreachable or
        heavily restricted.
      - ``pyodide-build.yaml`` manifests, or files with ``import pyodide`` /
        ``import js`` (the Pyodide <-> browser bridge) are treated as
        ``sandbox``: code executes inside the browser's WebAssembly isolate.
      - Host-global access density counts the Pyodide/IPython/Colab surface
        (``js.``, ``pyodide.``, ``IPython.``, ``google.colab.``).

  * **Go sandbox signals**
      - ``go.mod`` modules whose path contains ``tinygo`` → sandbox (TinyGo
        targets embedded/WASM runtimes without a full OS surface).
      - Files with a ``//go:build js`` or ``//go:build wasm`` constraint line
        (or the legacy ``// +build js`` / ``// +build wasm``) → sandbox.

The existing Node/JS detection and the ``server`` / ``build`` / ``unknown``
buckets are untouched.

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
    r"\b(figma|chrome|browser|vscode|Deno|WebAssembly|browserAction|runtime"
    # Python host globals. ``pyodide`` and ``IPython`` are distinctive enough
    # to count even in mixed-language trees; ``js`` and ``google`` are too
    # common as filename / domain substrings and are handled by the Pyodide
    # bridge content-signal instead.
    r"|pyodide|IPython)"
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

    # Python: Pyodide build manifest → sandbox for everything under it.
    for py_sb in list(workdir.rglob("pyodide-build.yaml")) + list(
        workdir.rglob("pyodide-build.yml")
    ):
        out.append((str(py_sb.parent), "sandbox"))

    # Python: presence of a jupyter_notebook_config.py marks the tree as a
    # kernel-hosted sandbox.
    for jup in workdir.rglob("jupyter_notebook_config.py"):
        out.append((str(jup.parent), "sandbox"))

    # Go: go.mod whose module path mentions tinygo → sandbox (WASM/TinyGo).
    for gm in workdir.rglob("go.mod"):
        try:
            text = gm.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("module ") and "tinygo" in stripped.lower():
                out.append((str(gm.parent), "sandbox"))
                break

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

    # 3) Language-specific content signals.
    # Python: Pyodide bridge imports are a strong sandbox indicator.
    if path.suffix == ".py":
        if _PYODIDE_BRIDGE_RX.search(src):
            return "sandbox"
    # Go: //go:build js|wasm constraint (or legacy // +build js|wasm).
    if path.suffix == ".go":
        if _GO_WASM_BUILD_RX.search(src):
            return "sandbox"

    # 4) Content signal: dense use of a host-managed global.
    hits = set()
    for m in _HOST_GLOBAL_RX.finditer(src):
        hits.add(m.group(0))
        if len(hits) >= _HOST_GLOBAL_DENSITY:
            return "sandbox"

    return "unknown"


# Python Pyodide bridge: either `import pyodide` / `from pyodide ...`, or
# `import js` (the Pyodide-provided browser bridge — in normal CPython code
# `import js` would just ImportError).
_PYODIDE_BRIDGE_RX = re.compile(
    r"""(?mx)
    ^\s*(?:
        import\s+pyodide\b
      | from\s+pyodide(?:\.[\w.]+)?\s+import\s+
      | import\s+js\b
      | from\s+js\s+import\s+
    )
    """,
)

# Go build constraints that target WASM / JS runtimes. Matches both the new
# ``//go:build js`` / ``//go:build wasm`` form (possibly ANDed with others)
# and the legacy ``// +build js`` / ``// +build wasm``.
_GO_WASM_BUILD_RX = re.compile(
    r"""(?mx)
    ^\s*//\s*(?:go:build|\+build)\s+[^\n]*\b(?:js|wasm)\b
    """,
)
