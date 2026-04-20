"""Tests for the LLM judge — uses a fake Context that implements .sample()."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from mception.config import settings
from mception.engines.dispatch import run_audit
from mception.llm_judge import (
    JudgeResult,
    _extract_text,
    _parse_verdict,
    classify,
    finding_from_verdict,
)


@dataclass
class FakeSamplingResult:
    text: str


class FakeCtx:
    """Minimal stand-in for a FastMCP Context — only implements .sample()."""

    def __init__(self, reply_text: str, raise_exc: Exception | None = None):
        self._reply = reply_text
        self._raise = raise_exc
        self.calls: list[dict] = []

    async def sample(self, messages, system_prompt=None, max_tokens=None, temperature=None):
        if self._raise is not None:
            raise self._raise
        self.calls.append(
            {
                "messages": messages,
                "system_prompt": system_prompt,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        )
        return FakeSamplingResult(text=self._reply)


# ---------- unit tests for pure helpers ----------


def test_parse_verdict_strict_json():
    r = _parse_verdict('{"verdict":"suspicious","reason":"hidden imperative"}')
    assert r is not None and r.verdict == "suspicious"
    assert "hidden" in r.reason


def test_parse_verdict_embedded_in_prose():
    r = _parse_verdict('Sure! {"verdict":"malicious","reason":"x"} done.')
    assert r is not None and r.verdict == "malicious"


def test_parse_verdict_rejects_bad_label():
    assert _parse_verdict('{"verdict":"bad","reason":"x"}') is None


def test_parse_verdict_rejects_non_json():
    assert _parse_verdict("just prose") is None


def test_extract_text_from_object():
    assert _extract_text(FakeSamplingResult(text="hello")) == "hello"


def test_extract_text_from_dict_content_list():
    assert (
        _extract_text({"content": [{"type": "text", "text": "hi"}]})
        == "hi"
    )


def test_finding_from_clean_is_none():
    r = JudgeResult(verdict="clean", reason="ok")
    assert finding_from_verdict(r, kind="tool", name="x", location="l", snippet="s") is None


def test_finding_from_suspicious_is_medium():
    r = JudgeResult(verdict="suspicious", reason="looks off")
    f = finding_from_verdict(r, kind="tool", name="x", location="l", snippet="s")
    assert f is not None
    assert f.rule_id == "MCP-LLM-001"
    assert f.severity.value == "medium"
    assert f.confidence.value == "suspected"


def test_finding_from_malicious_is_high_but_suspected():
    r = JudgeResult(verdict="malicious", reason="direct exfil instruction")
    f = finding_from_verdict(r, kind="tool", name="x", location="l", snippet="s")
    assert f is not None
    assert f.rule_id == "MCP-LLM-002"
    assert f.severity.value == "high"
    # Advisory-only — never Confirmed.
    assert f.confidence.value == "suspected"


# ---------- async classify() — graceful degradation ----------


@pytest.mark.asyncio
async def test_classify_returns_none_if_ctx_is_none():
    assert await classify(None, text="x", kind="tool", name="t") is None


@pytest.mark.asyncio
async def test_classify_returns_none_on_sampling_exception():
    ctx = FakeCtx(reply_text="", raise_exc=RuntimeError("host does not support sampling"))
    assert await classify(ctx, text="x", kind="tool", name="t") is None


@pytest.mark.asyncio
async def test_classify_returns_none_on_malformed_reply():
    ctx = FakeCtx(reply_text="I'm not going to answer that.")
    assert await classify(ctx, text="x", kind="tool", name="t") is None


@pytest.mark.asyncio
async def test_classify_happy_path():
    ctx = FakeCtx(reply_text='{"verdict":"suspicious","reason":"weirdly terse"}')
    r = await classify(ctx, text="Does stuff.", kind="tool", name="x")
    assert r is not None and r.verdict == "suspicious"
    # Also verify the judge sent a proper prompt.
    assert ctx.calls and "BEGIN" in ctx.calls[0]["messages"]
    assert ctx.calls[0]["temperature"] == 0.1


# ---------- end-to-end via dispatcher ----------


@pytest.mark.asyncio
async def test_judge_wired_into_metadata_engine(tmp_path: Path, monkeypatch):
    """When enabled + ctx + no static hit, judge adds MCP-LLM finding."""
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "enable_llm_judge", True)
    src = tmp_path / "src"
    src.mkdir()
    (src / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def harmless(a: int, b: int) -> int:
    """Adds two numbers and returns the sum."""
    return a + b
''',
        encoding="utf-8",
    )
    ctx = FakeCtx(reply_text='{"verdict":"suspicious","reason":"vibe check"}')
    r = await run_audit(str(src), target_kind="local", mcp_ctx=ctx)
    rule_ids = {f.rule_id for f in r.findings}
    assert "MCP-LLM-001" in rule_ids
    # Judge is advisory only — verdict should be Safe or Caution, not Unsafe,
    # since the only finding is Suspected/Medium from the judge.
    assert r.score.verdict.value in ("safe_to_use", "use_with_caution")


@pytest.mark.asyncio
async def test_judge_skipped_when_disabled(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "enable_llm_judge", False)
    src = tmp_path / "src"
    src.mkdir()
    (src / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def t() -> int:
    """clean."""
    return 1
''',
        encoding="utf-8",
    )
    ctx = FakeCtx(reply_text='{"verdict":"malicious","reason":"would only fire if enabled"}')
    r = await run_audit(str(src), target_kind="local", mcp_ctx=ctx)
    assert not any(f.rule_id.startswith("MCP-LLM-") for f in r.findings)
    assert ctx.calls == []


@pytest.mark.asyncio
async def test_judge_skipped_when_static_rules_hit(tmp_path: Path, monkeypatch):
    """If an item already has a Confirmed finding (e.g. invisible Unicode),
    don't spend a sampling call asking the model — it won't add signal."""
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "enable_llm_judge", True)
    src = tmp_path / "src"
    src.mkdir()
    (src / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def t() -> int:
    """Reads.\u200b hidden."""
    return 1
''',
        encoding="utf-8",
    )
    ctx = FakeCtx(reply_text='{"verdict":"malicious","reason":"x"}')
    r = await run_audit(str(src), target_kind="local", mcp_ctx=ctx)
    # Static rule fires …
    assert any(f.rule_id == "MCP-TP-001" for f in r.findings)
    # … and the judge is skipped for this item.
    assert ctx.calls == []


@pytest.mark.asyncio
async def test_judge_graceful_when_host_lacks_sampling(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "data_dir", tmp_path / "data")
    monkeypatch.setattr(settings, "enable_llm_judge", True)
    src = tmp_path / "src"
    src.mkdir()
    (src / "s.py").write_text(
        '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def t() -> int:
    """harmless."""
    return 1
''',
        encoding="utf-8",
    )
    ctx = FakeCtx(reply_text="", raise_exc=RuntimeError("sampling not supported"))
    r = await run_audit(str(src), target_kind="local", mcp_ctx=ctx)
    # No LLM findings — but also no crash, no INCONCLUSIVE.
    assert not any(f.rule_id.startswith("MCP-LLM-") for f in r.findings)
    assert r.score.verdict.value in ("safe_to_use", "use_with_caution")
