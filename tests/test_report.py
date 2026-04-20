"""Report renderer smoke tests + golden-ish checks."""

from __future__ import annotations

import json

from mception.findings import Category, Confidence, Evidence, Finding, Severity
from mception.report import AuditReport, to_json, to_markdown, to_sarif
from mception.scoring import score_findings


def _sample_report() -> AuditReport:
    findings = [
        Finding(
            rule_id="MCP-TP-001",
            title="Hidden instruction in tool description",
            category=Category.TOOL_POISONING,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            description="The tool description contains an invisible instruction block.",
            remediation="Remove the hidden block; re-publish with a clean description.",
            evidence=[Evidence(location="tools[getFile].description", snippet="...SECRET...")],
            cwe=["CWE-74"],
            owasp_mcp="MCP01:2025",
            references=["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
        )
    ]
    s = score_findings(findings)
    return AuditReport(
        audit_id="aud_testtesttesttest",
        target="local:/tmp/mcp-server",
        target_kind="local",
        generated_at="2026-04-20T00:00:00+00:00",
        mception_version="0.1.0",
        profile="standard",
        score=s,
        findings=findings,
    )


def test_markdown_contains_verdict_and_finding():
    r = _sample_report()
    md = to_markdown(r)
    assert "UNSAFE TO USE" in md
    assert "MCP-TP-001" in md
    assert "Hidden instruction" in md


def test_json_roundtrip():
    r = _sample_report()
    j = to_json(r)
    obj = json.loads(j)
    assert obj["score"]["verdict"] == "unsafe_to_use"
    assert obj["findings"][0]["rule_id"] == "MCP-TP-001"


def test_sarif_has_required_fields():
    r = _sample_report()
    doc = json.loads(to_sarif(r))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "mception"
    assert run["results"][0]["ruleId"] == "MCP-TP-001"
    assert run["results"][0]["level"] == "error"
