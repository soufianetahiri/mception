"""Multi-language support: TS/JS + Go + Rust extraction and SAST."""

from __future__ import annotations

from pathlib import Path

from mception.engines.source_parse import extract_from_workdir
from mception.rules.go_rules import scan_go_file
from mception.rules.node_rules import scan_node_file
from mception.rules.rust_rules import scan_rust_file
from mception.rules.supply_chain import parse_manifests, rule_typosquat, DependencySummary


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


def test_typosquat_crosses_ecosystems():
    # Rust crates ecosystem, near miss of tokio.
    deps = [DependencySummary(name="tokyo", version="1.0", ecosystem="crates")]
    r = list(rule_typosquat(deps))
    assert r and "tokio" in r[0].description
