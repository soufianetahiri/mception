"""Metadata engine — applies text/param rules to statically-extracted MCP surfaces."""

from __future__ import annotations

from ..findings import Finding
from ..rules.text_rules import (
    TextContext,
    rule_ansi_escapes,
    rule_auto_approve_bait,
    rule_cross_tool_reference,
    rule_injection_phrases,
    rule_invisible_unicode,
    rule_param_name_abuse,
    rule_secret_references,
)
from .base import EngineResult, TargetContext
from .source_parse import extract_from_workdir


class MetadataEngine:
    name = "metadata"

    async def run(self, target_ctx: TargetContext) -> EngineResult:
        result = EngineResult(engine=self.name)
        if target_ctx.workdir is None:
            result.inconclusive = True
            result.notes.append("No workdir; metadata engine needs a fetched target.")
            return result

        items = extract_from_workdir(target_ctx.workdir)
        if not items:
            result.notes.append(
                "Extracted zero MCP tool/resource/prompt surfaces statically. "
                "Server may use dynamic registration (e.g., loaded from config at runtime)."
            )
            # Not inconclusive by itself — we can still score the target as 'no findings' = safe,
            # BUT we downgrade confidence by leaving a meta note so humans see it.
            return result

        tool_names = {it.name for it in items if it.kind == "tool"}
        findings: list[Finding] = []

        for it in items:
            rel = (
                str(it.source_file.relative_to(target_ctx.workdir))
                if target_ctx.workdir in it.source_file.parents or it.source_file == target_ctx.workdir
                else str(it.source_file)
            )
            loc = f"{it.kind}[{it.name}]@{rel}:{it.line}"
            text = it.description or ""
            if text:
                tctx = TextContext(text=text, location=loc, source_file=rel, source_line=it.line)
                findings.extend(rule_invisible_unicode(tctx))
                findings.extend(rule_ansi_escapes(tctx))
                findings.extend(rule_injection_phrases(tctx))
                findings.extend(rule_secret_references(tctx))
                if it.kind == "tool":
                    findings.extend(rule_cross_tool_reference(text, it.name, tool_names, loc))
            if it.kind == "tool":
                findings.extend(rule_auto_approve_bait(it.name, it.description, loc))
                params = set(it.extras.get("params", []))
                if params:
                    findings.extend(rule_param_name_abuse(params, f"tools[{it.name}].inputSchema"))

        result.findings = findings
        result.notes.append(
            f"Extracted {len(items)} MCP surfaces: "
            f"{sum(1 for i in items if i.kind == 'tool')} tools, "
            f"{sum(1 for i in items if i.kind == 'resource')} resources, "
            f"{sum(1 for i in items if i.kind == 'prompt')} prompts."
        )
        return result
