# Changelog

All notable changes to mception.

## [0.5.0] — 2026-04-22

### Added
- **Multi-language SAST expansion.**
  - Ruby rule set (`RUBY-CMDI-001/002`, `RUBY-DES-001`, `RUBY-SSRF-001`, `RUBY-PATH-001`, `RUBY-AUTH-001`) covering backticks, `%x{}`, `system`/`exec`, `eval`/`instance_eval`, `Marshal.load`, `YAML.unsafe_load`, open-uri SSRF, `VERIFY_NONE`.
  - Rust rule set expanded with `RUST-DES-001` (bincode / rmp_serde / serde_json), `RUST-FFI-001` (unsafe `libc::system`/`libc::exec*`), `RUST-AUTH-001` (`danger_accept_invalid_certs`), `RUST-PATH-001` (dynamic `fs::File::open`).
  - Go `GO-PLUG-001` for `plugin.Open` (runtime loading of shared objects).
- **Import-binding trackers per language.** Sinks are only flagged when the sink's name is actually bound to the dangerous module: `child_process` for Node, `subprocess`/`os`/`pickle`/`yaml`/`marshal` for Python, `os/exec`/`plugin`/`encoding/gob` for Go (alias-aware), `std::process::Command` for Rust, `Open3`/`open-uri` for Ruby. Eliminates the classic `regex.exec()` → `child_process.exec` false positive.
- **Ecosystem-agnostic surface classifier** (`src/mception/rules/surface.py`). Every source file is tagged as `server` / `sandbox` / `build` / `unknown` based on manifest shape and host-global density. Sandbox surfaces (Figma plugin, browser extension, VS Code extension, Cloudflare Worker, Deno Deploy, Pyodide, TinyGo/WASM) demote or suppress sinks that are unreachable in that runtime. No vendor names hardcoded.
- **Scope-aware dependency analysis.** `DependencySummary.scope` distinguishes `runtime` / `dev` / `optional` / `peer` / `build` across npm (`devDependencies`, `optionalDependencies`, `peerDependencies`), pyproject (`tool.poetry.group.*`, PEP 735 `dependency-groups`, `optional-dependencies`), Cargo (`[dev-dependencies]`, `[build-dependencies]`), and `go.mod` (`// indirect`). Dev-scope CVEs from OSV are demoted one severity and tagged `[dev-only]`, and no longer drive verdicts.
- **Per-repo suppression via `.mception.yml`.** Match by rule ID glob, path glob, dependency, category, or scope. Suppressed findings remain in the report under `AuditReport.suppressed_findings` with a `suppression_reason`, never silently dropped. Documented in [docs/example.mception.yml](docs/example.mception.yml).
- **Fixture-based FP harness** (`tests/fixtures/servers/` + `tests/test_fp_harness.py`). Six known-good/known-bad fixtures exercise the regressions we care about (regex.exec, real exec, sandbox eval, dev-only OSV, python subprocess, python method-exec). Offline-mode autouse to avoid network calls during tests.

### Changed
- **Scoring rebalanced.**
  - Critical auto-fail now requires `Confidence >= LIKELY`. Previously any `Suspected` critical could unilaterally fail a verdict.
  - Dependency-vuln findings are capped per `(package, version)` bucket with separate tiers for runtime (60, one HIGH-equivalent) and dev (5, one LOW-equivalent). One outdated dep triggering 11 CVE advisories no longer saturates the score.
- **`NODE-CMDI-002` (`eval` / `new Function` / `vm.*`)** demotes from CRITICAL to MEDIUM/SUSPECTED on sandbox surfaces and to LOW on build-tool configs.
- **`MCP-SUP-006`** (missing lockfile) now skipped for registry-artifact targets (`target_kind=npm|pypi|crates|rubygems`) — these package formats strip lockfiles on publish by design.
- **`MCP-SUP-005`** (floating version ranges) now emits two findings: runtime (medium) and dev/build (info), so dev-only floats no longer drive the verdict.
- **OSV ecosystem coverage** extended to Go and crates.io.

### Fixed
- `NODE-CMDI-001` no longer false-flags `RegExp.prototype.exec()` as `child_process.exec()` (`(?<![.\w])` lookbehind + import-binding check).
- Go `exec.Command` false positives on local variables named `exec` (no `import "os/exec"` in the file).
- Single-line `require path v1.2.3` forms in `go.mod` were previously ignored.

### Figma-console-mcp audit, before → after
- 16 findings (1C / 1H / 14M) / score 0.0 / `unsafe_to_use` → 15 findings (0C / 0H / 2M / 12L / 1I) / score 55.0.
- 13 of the original 16 findings were false positives; all are now resolved or legitimate signal.

### Tests
- 115 → 168 (+53 across 4 parallel tranches).

## [0.4.0] — earlier
- `.mcpb` bundle for one-click Claude Desktop install.
- Single-file PyInstaller bundle.
- Full env-var and profile documentation.

(See git log for pre-0.5.0 history.)
