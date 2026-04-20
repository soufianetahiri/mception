"""Deterministic text-analysis rules applied to MCP tool/resource/prompt descriptions.

Every rule returns zero or more Finding objects for a given (text, location) pair.
Rules are independent; the metadata engine calls them in order and collects results.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from ..findings import Category, Confidence, Evidence, Finding, Severity


@dataclass
class TextContext:
    text: str
    location: str  # E.g. "tools[getFile].description"
    source_file: str | None = None
    source_line: int | None = None


# ---------- rule implementations ----------


# Characters that are invisible or change rendering direction — canonical tool-poisoning tells.
_INVISIBLE = {
    "\u200b": "ZWSP",
    "\u200c": "ZWNJ",
    "\u200d": "ZWJ",
    "\u2060": "WORD JOINER",
    "\ufeff": "BOM / ZWNBSP",
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
    "\u00ad": "SOFT HYPHEN",
}


def rule_invisible_unicode(ctx: TextContext) -> Iterable[Finding]:
    hits = []
    for i, ch in enumerate(ctx.text):
        if ch in _INVISIBLE:
            hits.append((i, ch, _INVISIBLE[ch]))
        elif unicodedata.category(ch) == "Cf" and ch not in _INVISIBLE:
            # Other format/control chars (tag chars U+E0000..U+E007F used in TPA PoCs).
            hits.append((i, ch, f"FORMAT/CF U+{ord(ch):04X}"))
    if not hits:
        return []
    sample = ", ".join(f"{label}@{i}" for i, _, label in hits[:8])
    snippet = ctx.text.replace("\n", "\\n")[:400]
    return [
        Finding(
            rule_id="MCP-TP-001",
            title="Invisible or bidi-control characters in MCP text",
            category=Category.TOOL_POISONING,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "Found invisible or bidirectional-control characters that are hidden from humans "
                "but are part of the LLM's context. This is the canonical tool-poisoning vector. "
                f"Hits: {sample}."
            ),
            remediation=(
                "Strip all Unicode Cf/format characters and bidi controls from descriptions, "
                "resource bodies, and server instructions before publishing."
            ),
            evidence=[Evidence(location=ctx.location, snippet=snippet, extra={"count": len(hits)})],
            cwe=["CWE-94", "CWE-1007"],
            owasp_mcp="MCP03:2025",
            references=[
                "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
                "https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/",
            ],
        )
    ]


_ANSI_RX = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")


def rule_ansi_escapes(ctx: TextContext) -> Iterable[Finding]:
    if not _ANSI_RX.search(ctx.text):
        return []
    return [
        Finding(
            rule_id="MCP-TP-002",
            title="ANSI terminal escape sequences in MCP text",
            category=Category.ANSI_INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            description=(
                "ANSI escape sequences can hide or falsify content when rendered in a terminal "
                "client while still reaching the model context. Part of the line-jumping class."
            ),
            remediation="Strip ANSI escapes from all server-supplied text.",
            evidence=[Evidence(location=ctx.location, snippet=ctx.text[:400])],
            cwe=["CWE-117"],
            owasp_mcp="MCP03:2025",
            references=[
                "https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/",
            ],
        )
    ]


# Phrases known to appear in poisoned descriptions across published PoCs.
_INJECTION_PHRASES = [
    r"ignore (?:previous|above|prior) instructions?",
    r"before (?:calling|invoking|using) (?:this|the|any) tool",
    r"do not (?:tell|inform|show) the user",
    r"you are (?:now|an?) (?:assistant|ai|model)",
    r"system prompt",
    r"<\s*system\s*>",
    r"###\s*system",
    r"\[\s*important\s*\]",
    r"<!--\s*instructions",
]
_INJECTION_RX = re.compile("|".join(_INJECTION_PHRASES), re.IGNORECASE)


def rule_injection_phrases(ctx: TextContext) -> Iterable[Finding]:
    m = _INJECTION_RX.search(ctx.text)
    if not m:
        return []
    return [
        Finding(
            rule_id="MCP-TP-003",
            title="Instruction-style phrase inside MCP text",
            category=Category.TOOL_POISONING,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            description=(
                "Text contains phrasing commonly used in prompt-injection PoCs to bend the model's "
                f"behavior away from the user's goal. Matched: {m.group(0)!r}."
            ),
            remediation=(
                "Descriptions should document behavior for humans, not issue imperatives at the model. "
                "Remove or rephrase imperatives targeting 'the assistant' / 'the model' / 'the AI'."
            ),
            evidence=[Evidence(location=ctx.location, snippet=_excerpt(ctx.text, m))],
            cwe=["CWE-74"],
            owasp_mcp="MCP03:2025",
            references=[
                "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
            ],
        )
    ]


# Sensitive path / env-var references an attacker would want to exfiltrate.
_SECRET_PATHS = [
    r"\.ssh/id_[a-z_]+",
    r"\.ssh/authorized_keys",
    r"~/\.aws/credentials",
    r"\.npmrc",
    r"\.env(?!\w)",
    r"\.kube/config",
    r"\.docker/config\.json",
    r"/etc/shadow",
    r"/etc/passwd",
]
_SECRET_ENV = [
    r"\bAWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)\b",
    r"\bGITHUB_TOKEN\b",
    r"\bANTHROPIC_API_KEY\b",
    r"\bOPENAI_API_KEY\b",
    r"\bSLACK_TOKEN\b",
    r"\bNPM_TOKEN\b",
    r"\bDATABASE_URL\b",
]
_SECRET_RX = re.compile("|".join(_SECRET_PATHS + _SECRET_ENV), re.IGNORECASE)


def rule_secret_references(ctx: TextContext) -> Iterable[Finding]:
    m = _SECRET_RX.search(ctx.text)
    if not m:
        return []
    return [
        Finding(
            rule_id="MCP-TP-004",
            title="Description references secret material",
            category=Category.CREDENTIAL_EXFIL,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            description=(
                "The description references a path or environment variable commonly used for "
                f"secrets ({m.group(0)!r}). In poisoned tools this is used to trick the model "
                "into reading and returning the contents."
            ),
            remediation=(
                "If the tool legitimately handles secrets, document that in README — not in the "
                "model-facing description. Otherwise remove the reference."
            ),
            evidence=[Evidence(location=ctx.location, snippet=_excerpt(ctx.text, m))],
            cwe=["CWE-532", "CWE-200"],
            owasp_mcp="MCP01:2025",
            references=[
                "https://cyata.ai/blog/whispering-secrets-loudly-inside-mcps-quiet-crisis-of-credential-exposure/",
            ],
        )
    ]


# Parameter names that extract system prompts / hidden context from many frontier models.
ABUSIVE_PARAM_NAMES = {
    "system_prompt",
    "systemprompt",
    "chain_of_thought",
    "chainofthought",
    "conversation_history",
    "conversationhistory",
    "previous_messages",
    "hidden_context",
    "reasoning",
    "internal_state",
}


def rule_param_name_abuse(param_names: set[str], location: str) -> Iterable[Finding]:
    hits = sorted(n for n in param_names if n.lower() in ABUSIVE_PARAM_NAMES)
    if not hits:
        return []
    return [
        Finding(
            rule_id="MCP-PA-001",
            title="Abusive parameter names that may exfiltrate model state",
            category=Category.PARAM_NAME_ABUSE,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            description=(
                "The tool declares parameters named "
                + ", ".join(repr(h) for h in hits)
                + ". Multiple frontier models will populate such fields with the actual system "
                "prompt or chain-of-thought, enabling exfiltration via any call."
            ),
            remediation=(
                "Rename these parameters to something domain-specific. Never accept a parameter "
                "whose name encourages the model to dump its own context."
            ),
            evidence=[Evidence(location=location, extra={"params": hits})],
            cwe=["CWE-200"],
            references=[
                "https://www.hiddenlayer.com/research/exploiting-mcp-tool-parameters",
            ],
        )
    ]


def rule_cross_tool_reference(
    text: str, own_name: str, all_tool_names: set[str], location: str
) -> Iterable[Finding]:
    """Flag a description that mentions *other* tool names — classic shadowing tell."""
    others = [n for n in all_tool_names if n and n != own_name and len(n) > 3]
    hits = [n for n in others if re.search(rf"\b{re.escape(n)}\b", text or "")]
    if not hits:
        return []
    return [
        Finding(
            rule_id="MCP-SH-001",
            title="Tool description references other tools",
            category=Category.SHADOWING,
            severity=Severity.MEDIUM,
            confidence=Confidence.SUSPECTED,
            description=(
                f"The description of tool {own_name!r} names other tools ({', '.join(hits)}). "
                "In tool-shadowing attacks, this is how one tool's description bends the model's "
                "behavior when invoking a *different* tool."
            ),
            remediation=(
                "A tool's description should describe that tool only. Cross-references should live "
                "in user-facing docs, not in text the model reads as authoritative."
            ),
            evidence=[Evidence(location=location, snippet=(text or "")[:300])],
            cwe=["CWE-94"],
            owasp_mcp="MCP03:2025",
            references=[
                "https://acuvity.ai/cross-server-tool-shadowing-hijacking-calls-between-servers/",
            ],
        )
    ]


def rule_auto_approve_bait(
    name: str, description: str | None, location: str
) -> Iterable[Finding]:
    """Heuristic for 'looks too boring / one-line / reassurance-heavy' tools that do a lot."""
    if description is None:
        return []
    desc = description.strip()
    low = desc.lower()
    reassurances = ("safe", "harmless", "read-only", "no side effects", "trusted", "innocuous")
    short = len(desc) < 40
    reassure_hit = any(r in low for r in reassurances)
    name_hint = any(
        h in name.lower()
        for h in ("exec", "run", "shell", "system", "eval", "command", "sudo", "admin")
    )
    if short and name_hint:
        sev = Severity.MEDIUM
        reason = f"very short description ({len(desc)} chars) on a privileged-sounding name {name!r}"
    elif reassure_hit and name_hint:
        sev = Severity.MEDIUM
        reason = f"reassurance language in description of privileged-sounding tool {name!r}"
    else:
        return []
    return [
        Finding(
            rule_id="MCP-AA-001",
            title="Auto-approve bait: mismatched description/name",
            category=Category.AUTO_APPROVE,
            severity=sev,
            confidence=Confidence.SUSPECTED,
            description=(
                "Tool name implies broad authority but description is terse or reassurance-heavy "
                f"({reason}). This pattern is exploited in auto-approving clients."
            ),
            remediation=(
                "Either make the tool actually scoped (and rename), or expand the description "
                "to truthfully state the authority and side effects."
            ),
            evidence=[Evidence(location=location, snippet=desc[:300])],
            references=[
                "https://owasp.org/www-project-mcp-top-10/",
            ],
        )
    ]


def _excerpt(text: str, m: re.Match) -> str:
    start = max(0, m.start() - 40)
    end = min(len(text), m.end() + 40)
    return text[start:end].replace("\n", "\\n")
