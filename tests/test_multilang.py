"""Multi-language support: TS/JS + Go + Rust extraction and SAST."""

from __future__ import annotations

import ast
from pathlib import Path

from mception.engines.source_parse import extract_from_workdir
from mception.rules.code_rules import (
    CodeContext,
    collect_import_bindings,
    collect_params,
    iter_tool_handlers,
    rule_command_injection,
    rule_unsafe_deserialization,
)
from mception.rules.go_rules import scan_go_file
from mception.rules.node_rules import scan_node_file
from mception.rules.ruby_rules import scan_ruby_file
from mception.rules.rust_rules import scan_rust_file
from mception.rules.supply_chain import parse_manifests, rule_typosquat, DependencySummary
from mception.rules.surface import classify_surface


# ---------- TS/JS extraction ----------


def test_ts_addtool_extraction(tmp_path: Path):
    (tmp_path / "server.ts").write_text(
        '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "s", version: "1.0" });
server.addTool({
  name: "read_file",
  description: "Read a file and return the contents.",
  inputSchema: { type: "object", properties: {} },
});
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.kind == "tool" and i.name == "read_file" for i in items)


def test_ts_positional_tool_extraction(tmp_path: Path):
    (tmp_path / "s.ts").write_text(
        '''
server.tool("list_users", "Lists all users.", { type: "object" }, async () => []);
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.name == "list_users" and "Lists all users" in (i.description or "") for i in items)


def test_ts_resource_prompt_extraction(tmp_path: Path):
    (tmp_path / "s.ts").write_text(
        '''
server.addResource({ uri: "x://y", description: "The Y resource." });
server.addPrompt({ name: "greet", description: "A greeting prompt." });
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    kinds = {(i.kind, i.name) for i in items}
    assert ("resource", "x://y") in kinds
    assert ("prompt", "greet") in kinds


# ---------- Go extraction ----------


def test_go_newtool_extraction(tmp_path: Path):
    (tmp_path / "main.go").write_text(
        '''
package main

import "github.com/mark3labs/mcp-go/mcp"

func main() {
    tool := mcp.NewTool("fetch_url",
        mcp.WithDescription("Fetch a URL and return its body."),
    )
    _ = tool
}
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.kind == "tool" and i.name == "fetch_url" for i in items)
    tool = next(i for i in items if i.name == "fetch_url")
    assert "Fetch a URL" in (tool.description or "")


def test_go_tool_struct_extraction(tmp_path: Path):
    (tmp_path / "tools.go").write_text(
        '''
var t = mcp.Tool{
    Name:        "do_thing",
    Description: "Performs a thing.",
}
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.name == "do_thing" for i in items)


# ---------- Rust extraction ----------


def test_rust_attribute_tool_extraction(tmp_path: Path):
    (tmp_path / "lib.rs").write_text(
        '''
use rmcp::tool;

#[tool(description = "Greets the user.")]
async fn greet(name: String) -> String {
    format!("hello {}", name)
}
''',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.kind == "tool" and i.name == "greet" for i in items)


def test_rust_builder_tool_extraction(tmp_path: Path):
    (tmp_path / "main.rs").write_text(
        'let s = Server::new().tool("ping", "Health check.");',
        encoding="utf-8",
    )
    items = extract_from_workdir(tmp_path)
    assert any(i.name == "ping" for i in items)


# ---------- Node SAST rules ----------


def test_node_cmdi_template_string(tmp_path: Path):
    src = '''
import { exec } from "child_process";
exec(`ls ${userPath}`, (err, stdout) => {});
'''
    findings = scan_node_file(tmp_path / "s.ts", src, tmp_path)
    assert any(f.rule_id == "NODE-CMDI-001" and f.severity.value == "critical" for f in findings)


def test_node_eval(tmp_path: Path):
    src = 'const r = eval(userExpr);\n'
    findings = scan_node_file(tmp_path / "s.js", src, tmp_path)
    assert any(f.rule_id == "NODE-CMDI-002" for f in findings)


def test_node_ssrf_dynamic(tmp_path: Path):
    src = 'const r = await fetch(`https://example.com/${path}`);\n'
    findings = scan_node_file(tmp_path / "s.ts", src, tmp_path)
    assert any(f.rule_id == "NODE-SSRF-001" for f in findings)


def test_node_path_traversal(tmp_path: Path):
    src = 'import fs from "fs"; fs.readFile(userPath, cb);\n'
    findings = scan_node_file(tmp_path / "s.ts", src, tmp_path)
    assert any(f.rule_id == "NODE-PATH-001" for f in findings)


def test_node_tls_off(tmp_path: Path):
    src = 'const agent = new https.Agent({ rejectUnauthorized: false });'
    findings = scan_node_file(tmp_path / "s.ts", src, tmp_path)
    assert any(f.rule_id == "NODE-AUTH-001" for f in findings)


def test_node_static_literal_exec_not_critical(tmp_path: Path):
    # Fixed literal command should not be Critical — at most Suspected.
    src = 'const { execSync } = require("child_process"); execSync("ls -la");\n'
    findings = scan_node_file(tmp_path / "s.js", src, tmp_path)
    cmdi = [f for f in findings if f.rule_id == "NODE-CMDI-001"]
    # Either no finding or non-critical.
    assert all(f.severity.value != "critical" for f in cmdi)


# ---------- Go SAST rules ----------


def test_go_cmdi_sh_dash_c(tmp_path: Path):
    src = '''
package main
import "os/exec"
func run(user string) {
    exec.Command("sh", "-c", "ls "+user)
}
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert any(f.rule_id == "GO-CMDI-001" and f.severity.value == "critical" for f in findings)


def test_go_ssrf(tmp_path: Path):
    src = 'package main\nimport "net/http"\nfunc f(u string) { http.Get(u) }\n'
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert any(f.rule_id == "GO-SSRF-001" for f in findings)


def test_go_path(tmp_path: Path):
    src = 'package main\nimport "os"\nfunc f(p string) { os.ReadFile(p) }\n'
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert any(f.rule_id == "GO-PATH-001" for f in findings)


def test_go_bind_all(tmp_path: Path):
    src = 'package main\nimport "net/http"\nfunc main() { http.ListenAndServe(":8080", nil) }\n'
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert any(f.rule_id == "GO-AUTH-002" for f in findings)


def test_go_cmdi_import_binding_required(tmp_path: Path):
    # `exec` is a local variable here; os/exec is never imported, so `exec.Command`
    # must not be flagged.
    src = '''
package main

type Runner struct{}
func (r Runner) Command(args ...string) {}

func run(user string) {
    exec := Runner{}
    exec.Command("sh", "-c", user)
}
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert not any(f.rule_id == "GO-CMDI-001" for f in findings)


def test_go_cmdi_aliased_import(tmp_path: Path):
    # Aliased import — `exc.Command("sh","-c",user)` must be flagged.
    src = '''
package main
import exc "os/exec"
func run(user string) {
    exc.Command("sh", "-c", user)
}
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert any(
        f.rule_id == "GO-CMDI-001" and f.severity.value == "critical" for f in findings
    )


def test_go_cmdi_block_import_aliased(tmp_path: Path):
    # Aliased within a block import.
    src = '''
package main

import (
    "fmt"
    exc "os/exec"
)

func run(user string) {
    fmt.Println("x")
    exc.Command("sh", "-c", user)
}
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert any(f.rule_id == "GO-CMDI-001" for f in findings)


def test_go_cmdi_dot_qualifier_not_double_matched(tmp_path: Path):
    # `wrap.exec.Command(...)` where `wrap.exec` is a field — the leading `.`
    # should suppress the bare `exec.Command` match. os/exec is NOT imported here.
    src = '''
package main
type W struct{ exec interface{ Command(...string) } }
func run(w W, user string) { w.exec.Command("sh", "-c", user) }
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert not any(f.rule_id == "GO-CMDI-001" for f in findings)


def test_go_cmdi_suppressed_on_wasm_sandbox(tmp_path: Path, monkeypatch):
    # If surface classifier says "sandbox" (e.g. WASM build), exec.Command
    # findings are suppressed — syscall surface isn't reachable.
    import mception.rules.go_rules as gr

    monkeypatch.setattr(gr, "classify_surface", lambda p, s, w: "sandbox")
    src = '''
//go:build wasm

package main
import "os/exec"
func run(user string) { exec.Command("sh", "-c", user) }
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    assert not any(f.rule_id == "GO-CMDI-001" for f in findings)


def test_go_plugin_open_demoted_in_sandbox(tmp_path: Path, monkeypatch):
    import mception.rules.go_rules as gr

    monkeypatch.setattr(gr, "classify_surface", lambda p, s, w: "sandbox")
    src = '''
package main
import "plugin"
func load(p string) { plugin.Open(p) }
'''
    findings = scan_go_file(tmp_path / "m.go", src, tmp_path)
    plug = [f for f in findings if f.rule_id == "GO-PLUG-001"]
    assert plug and plug[0].severity.value == "medium"


# ---------- Rust SAST rules ----------


def test_rust_shell_command(tmp_path: Path):
    src = '''
use std::process::Command;
fn run(s: &str) {
    Command::new("sh").arg("-c").arg(s).output().unwrap();
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-CMDI-001" for f in findings)


def test_rust_ssrf(tmp_path: Path):
    src = 'fn f(u: &str) { let _ = reqwest::get(u); }\n'
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-SSRF-001" for f in findings)


def test_rust_cmdi_no_binding_no_flag(tmp_path: Path):
    # No `use std::process` import binding -> `Command::new` must not flag.
    src = '''
fn run() {
    Command::new("sh").arg("-c").arg("ls").output().unwrap();
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert not any(f.rule_id == "RUST-CMDI-001" for f in findings)


def test_rust_cmdi_dynamic_program(tmp_path: Path):
    src = '''
use std::process::Command;
fn run(user: &str) {
    Command::new(user).output().unwrap();
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-CMDI-001" for f in findings)


def test_rust_cmdi_wasm_demoted(tmp_path: Path):
    # wasm target -> severity demoted from critical to medium.
    src = '''
#![cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use std::process::Command;
fn run(s: &str) {
    Command::new("sh").arg("-c").arg(s).output().unwrap();
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    cmdi = [f for f in findings if f.rule_id == "RUST-CMDI-001"]
    assert cmdi and all(f.severity.value != "critical" for f in cmdi)


def test_rust_deser(tmp_path: Path):
    src = '''
use std::process::Command;
fn f(buf: &[u8]) {
    let _: MyType = bincode::deserialize(buf).unwrap();
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-DES-001" for f in findings)


def test_rust_ffi_libc_system(tmp_path: Path):
    src = '''
extern crate libc;
fn danger() {
    unsafe {
        libc::system(c_string.as_ptr());
    }
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-FFI-001" and f.severity.value == "critical" for f in findings)


def test_rust_weak_tls(tmp_path: Path):
    src = '''
fn client() {
    let c = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build().unwrap();
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-AUTH-001" for f in findings)


def test_rust_path_traversal(tmp_path: Path):
    src = '''
use std::fs;
fn f(p: &str) {
    let _ = fs::read_to_string(p);
}
'''
    findings = scan_rust_file(tmp_path / "l.rs", src, tmp_path)
    assert any(f.rule_id == "RUST-PATH-001" for f in findings)


# ---------- Ruby SAST rules ----------


def test_ruby_cmdi_system_interpolation(tmp_path: Path):
    src = '''
def run(user)
  system("ls #{user}")
end
'''
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    cmdi = [f for f in findings if f.rule_id == "RUBY-CMDI-001"]
    assert cmdi and any(f.severity.value == "critical" for f in cmdi)


def test_ruby_cmdi_backtick_interpolation(tmp_path: Path):
    src = '''
def run(user)
  `ls #{user}`
end
'''
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(f.rule_id == "RUBY-CMDI-001" for f in findings)


def test_ruby_cmdi_method_call_not_flagged(tmp_path: Path):
    # `obj.system(x)` is a custom method call, not Kernel#system — must not flag.
    src = '''
def run(user)
  @shell.system("ls " + user)
  obj.exec(cmd)
end
'''
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert not any(f.rule_id == "RUBY-CMDI-001" for f in findings)


def test_ruby_eval_dynamic(tmp_path: Path):
    src = 'def run(expr); eval("puts #{expr}"); end\n'
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(f.rule_id == "RUBY-CMDI-002" for f in findings)


def test_ruby_marshal_load(tmp_path: Path):
    src = 'def run(blob); Marshal.load(blob); end\n'
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(
        f.rule_id == "RUBY-DES-001" and f.severity.value == "critical" for f in findings
    )


def test_ruby_yaml_unsafe_load(tmp_path: Path):
    src = 'def run(s); YAML.unsafe_load(s); end\n'
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(f.rule_id == "RUBY-DES-001" for f in findings)


def test_ruby_ssrf_open_uri(tmp_path: Path):
    # Bare `open(url)` requires `open-uri` to be dangerous; flag only then.
    src = '''
require "open-uri"
def fetch(url)
  open(url).read
end
'''
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(f.rule_id == "RUBY-SSRF-001" for f in findings)


def test_ruby_ssrf_bare_open_without_require(tmp_path: Path):
    # No `require 'open-uri'` -> `open(path)` is File.open, not HTTP. Skip.
    src = '''
def read_file(path)
  open(path).read
end
'''
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert not any(f.rule_id == "RUBY-SSRF-001" for f in findings)


def test_ruby_path_traversal(tmp_path: Path):
    src = 'def read(p); File.read(p); end\n'
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(f.rule_id == "RUBY-PATH-001" for f in findings)


def test_ruby_weak_tls(tmp_path: Path):
    src = '''
http = Net::HTTP.new("example.com", 443)
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
'''
    findings = scan_ruby_file(tmp_path / "s.rb", src, tmp_path)
    assert any(f.rule_id == "RUBY-AUTH-001" for f in findings)


# ---------- SCA: go.mod + Cargo.toml parsing ----------


def test_parse_go_mod(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        '''
module example.com/foo

go 1.21

require (
    github.com/mark3labs/mcp-go v0.8.0
    github.com/spf13/cobra v1.7.0
)
''',
        encoding="utf-8",
    )
    deps, _ = parse_manifests(tmp_path)
    names = {(d.name, d.ecosystem) for d in deps}
    assert ("github.com/mark3labs/mcp-go", "go") in names
    assert ("github.com/spf13/cobra", "go") in names


def test_parse_cargo_toml(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '''
[package]
name = "x"
version = "0.1.0"

[dependencies]
tokio = "1.0"
serde = { version = "1.0", features = ["derive"] }
''',
        encoding="utf-8",
    )
    deps, _ = parse_manifests(tmp_path)
    names = {(d.name, d.ecosystem) for d in deps}
    assert ("tokio", "crates") in names
    assert ("serde", "crates") in names


def test_parse_go_mod_indirect_scope(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        '''
module example.com/foo

go 1.21

require (
    github.com/mark3labs/mcp-go v0.8.0
    github.com/spf13/cobra v1.7.0 // indirect
    github.com/davecgh/go-spew v1.1.1 // test
)

require github.com/direct/single v0.1.0

require github.com/indirect/single v0.2.0 // indirect

exclude github.com/bad/pkg v1.0.0

retract (
    v0.9.0
    v0.9.1
)
''',
        encoding="utf-8",
    )
    deps, _ = parse_manifests(tmp_path)
    scopes = {(d.name, d.scope) for d in deps if d.ecosystem == "go"}
    assert ("github.com/mark3labs/mcp-go", "runtime") in scopes
    assert ("github.com/spf13/cobra", "dev") in scopes
    assert ("github.com/direct/single", "runtime") in scopes
    assert ("github.com/indirect/single", "dev") in scopes
    # `// test`-tagged and retract/exclude entries should not appear.
    names = {d.name for d in deps if d.ecosystem == "go"}
    assert "github.com/davecgh/go-spew" not in names
    assert "github.com/bad/pkg" not in names


def test_typosquat_crosses_ecosystems():
    # Rust crates ecosystem, near miss of tokio.
    deps = [DependencySummary(name="tokyo", version="1.0", ecosystem="crates")]
    r = list(rule_typosquat(deps))
    assert r and "tokio" in r[0].description


# ---------- Python FP-reduction (tranche 3) ----------


def _py_ctx(src: str, tmp_path: Path, filename: str = "t.py") -> CodeContext:
    f = tmp_path / filename
    f.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    fn = next(iter(iter_tool_handlers(tree)))
    return CodeContext(
        workdir=tmp_path,
        source_file=f,
        func_node=fn,
        param_names=collect_params(fn),
        bindings=collect_import_bindings(tree),
        surface=classify_surface(f, src, tmp_path),
    )


def test_py_subprocess_shell_true_still_flagged(tmp_path: Path):
    # Real positive: subprocess.run(..., shell=True) with a dynamic (tainted)
    # arg must still come out as a command-injection finding.
    ctx = _py_ctx(
        '''
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("x")

@mcp.tool()
def run(user_cmd: str) -> bytes:
    return subprocess.run(user_cmd, shell=True, capture_output=True).stdout
''',
        tmp_path,
    )
    r = list(rule_command_injection(ctx))
    assert any(
        f.rule_id == "MCP-CMDI-001" and f.severity.value == "critical" for f in r
    )


def test_py_method_exec_not_flagged(tmp_path: Path):
    # `self.exec(x)` is a method call on an object — not the builtin exec.
    # AST chain is 'self.exec', which is not in _EVAL_SINKS, so the rule must
    # skip it even though the substring "exec(" appears.
    ctx = _py_ctx(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

class Runner:
    def exec(self, q): return q

@mcp.tool()
def run(q: str):
    r = Runner()
    return r.exec(q)
''',
        tmp_path,
    )
    r = list(rule_command_injection(ctx))
    assert r == [], f"expected no finding, got {[f.rule_id for f in r]}"


def test_py_bare_loads_without_import_not_flagged(tmp_path: Path):
    # Bare `loads(x)` with no `from pickle import loads` should NOT be flagged
    # — it's some other project-local function.
    ctx = _py_ctx(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

def loads(x):  # local helper, not pickle.loads
    return x

@mcp.tool()
def op(data: bytes):
    return loads(data)
''',
        tmp_path,
    )
    r = list(rule_unsafe_deserialization(ctx))
    assert r == []


def test_py_bare_loads_with_from_pickle_import_flagged(tmp_path: Path):
    # `from pickle import loads; loads(x)` IS the dangerous sink — the
    # import-binding tracker should resolve the bare call.
    ctx = _py_ctx(
        '''
from mcp.server.fastmcp import FastMCP
from pickle import loads
mcp = FastMCP("x")

@mcp.tool()
def op(data: bytes):
    return loads(data)
''',
        tmp_path,
    )
    r = list(rule_unsafe_deserialization(ctx))
    assert r and r[0].rule_id == "MCP-DES-001"


def test_py_aliased_subprocess_flagged(tmp_path: Path):
    # `import subprocess as sp; sp.run(x, shell=True)` must resolve via the
    # module alias.
    ctx = _py_ctx(
        '''
from mcp.server.fastmcp import FastMCP
import subprocess as sp
mcp = FastMCP("x")

@mcp.tool()
def run(user_cmd: str):
    return sp.run(user_cmd, shell=True)
''',
        tmp_path,
    )
    r = list(rule_command_injection(ctx))
    assert any(f.rule_id == "MCP-CMDI-001" for f in r)


def test_py_pyodide_file_demotes_eval(tmp_path: Path):
    # Pyodide bridge file → sandbox surface → eval demoted to MEDIUM.
    src = '''
from mcp.server.fastmcp import FastMCP
import pyodide
import js
mcp = FastMCP("x")

@mcp.tool()
def calc(expr: str):
    return eval(expr)
'''
    ctx = _py_ctx(src, tmp_path, filename="sandbox_tool.py")
    assert ctx.surface == "sandbox"
    r = list(rule_command_injection(ctx))
    evals = [f for f in r if f.rule_id == "MCP-CMDI-001"]
    assert evals, "eval should still flag, but demoted"
    assert all(f.severity.value == "medium" for f in evals)


def test_py_sandbox_suppresses_subprocess(tmp_path: Path):
    # Under a Pyodide bridge, subprocess findings are suppressed entirely.
    src = '''
from mcp.server.fastmcp import FastMCP
import pyodide
import subprocess
mcp = FastMCP("x")

@mcp.tool()
def run(cmd: str):
    return subprocess.run(cmd, shell=True)
'''
    ctx = _py_ctx(src, tmp_path, filename="sb.py")
    assert ctx.surface == "sandbox"
    r = [f for f in rule_command_injection(ctx) if f.rule_id == "MCP-CMDI-001"]
    assert r == []


# ---------- Surface classifier additions ----------


def test_surface_python_pyodide_bridge(tmp_path: Path):
    src = "import pyodide\nimport js\n"
    f = tmp_path / "bridge.py"
    f.write_text(src, encoding="utf-8")
    assert classify_surface(f, src, tmp_path) == "sandbox"


def test_surface_python_jupyter_manifest(tmp_path: Path):
    (tmp_path / "jupyter_notebook_config.py").write_text("c = {}", encoding="utf-8")
    kid = tmp_path / "sub" / "handler.py"
    kid.parent.mkdir()
    kid.write_text("x = 1", encoding="utf-8")
    assert classify_surface(kid, "x = 1", tmp_path) == "sandbox"


def test_surface_go_wasm_build_constraint(tmp_path: Path):
    src = "//go:build wasm\n\npackage main\nfunc main() {}\n"
    f = tmp_path / "w.go"
    f.write_text(src, encoding="utf-8")
    assert classify_surface(f, src, tmp_path) == "sandbox"


def test_surface_go_tinygo_module(tmp_path: Path):
    (tmp_path / "go.mod").write_text(
        "module github.com/example/tinygo-thing\n\ngo 1.21\n", encoding="utf-8"
    )
    src = "package main\nfunc main() {}\n"
    f = tmp_path / "m.go"
    f.write_text(src, encoding="utf-8")
    assert classify_surface(f, src, tmp_path) == "sandbox"


def test_surface_plain_python_unknown(tmp_path: Path):
    # Regression guard: a vanilla .py file must not be mistakenly sandboxed.
    src = "import os\ndef f(): return os.getcwd()\n"
    f = tmp_path / "plain.py"
    f.write_text(src, encoding="utf-8")
    assert classify_surface(f, src, tmp_path) == "unknown"
