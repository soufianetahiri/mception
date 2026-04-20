"""Metadata engine — applies text/param rules to statically-extracted MCP surfaces."""

from __future__ import annotations

from ..config import settings
from ..findings import Finding
from ..llm_judge import classify, finding_from_verdict
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
        judge_called = 0
        judge_hits = 0
        judge_enabled = settings.enable_llm_judge and target_ctx.mcp_ctx is not None

        for it in items:
            rel = (
                str(it.source_file.relative_to(target_ctx.workdir))
                if target_ctx.workdir in it.source_file.parents or it.source_file == target_ctx.workdir
                else str(it.source_file)
            )
            loc = f"{it.kind}[{it.name}]@{rel}:{it.line}"
            text = it.description or ""
            per_item_findings: list[Finding] = []
            if text:
                tctx = TextContext(text=text, location=loc, source_file=rel, source_line=it.line)
                per_item_findings.extend(rule_invisible_unicode(tctx))
                per_item_findings.extend(rule_ansi_escapes(tctx))
                per_item_findings.extend(rule_injection_phrases(tctx))
                per_item_findings.extend(rule_secret_references(tctx))
                if it.kind == "tool":
                    per_item_findings.extend(
                        rule_cross_tool_reference(text, it.name, tool_names, loc)
                    )
            if it.kind == "tool":
                per_item_findings.extend(rule_auto_approve_bait(it.name, it.description, loc))
                params = set(it.extras.get("params", []))
                if params:
                    per_item_findings.extend(
                        rule_param_name_abuse(params, f"tools[{it.name}].inputSchema")
                    )
            findings.extend(per_item_findings)

            # LLM judge: run only when enabled AND static rules found nothing objective on this
            # item. Skip items that already have a clear-cut finding (it's the ambiguous ones
            # where a model's opinion adds signal).
            if judge_enabled and text and not per_item_findings:
                judge_called += 1
                verdict = await classify(
                    target_ctx.mcp_ctx, text=text, kind=it.kind, name=it.name
                )
                if verdict is not None:
                    extra = finding_from_verdict(
                        verdict, kind=it.kind, name=it.name, location=loc, snippet=text
                    )
                    if extra is not None:
                        judge_hits += 1
                        findings.append(extra)

        result.findings = findings
        result.notes.append(
            f"Extracted {len(items)} MCP surfaces: "
            f"{sum(1 for i in items if i.kind == 'tool')} tools, "
            f"{sum(1 for i in items if i.kind == 'resource')} resources, "
            f"{sum(1 for i in items if i.kind == 'prompt')} prompts."
        )
        if judge_enabled:
            result.notes.append(
                f"LLM judge (MCP sampling): {judge_called} calls, {judge_hits} suspicious/malicious verdicts."
            )
        return result
