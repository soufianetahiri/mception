"""Finding model: the atomic unit of an mception audit."""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SUSPECTED = "suspected"


class Category(str, enum.Enum):
    TOOL_POISONING = "tool_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    RUG_PULL = "rug_pull"
    SHADOWING = "shadowing"
    CONFUSED_DEPUTY = "confused_deputy"
    CREDENTIAL_EXFIL = "credential_exfil"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    SUPPLY_CHAIN = "supply_chain"
    TRANSPORT = "transport"
    AUTH = "auth"
    EXFIL_SINK = "exfil_sink"
    SESSION = "session"
    LOGGING_LEAK = "logging_leak"
    SANDBOX_ESCAPE = "sandbox_escape"
    RESOURCE_PROMPT_INJECTION = "resource_prompt_injection"
    DEPENDENCY_VULN = "dependency_vuln"
    PROVENANCE = "provenance"
    DOS = "dos"
    INJECTION_DB = "injection_db"
    PARAM_NAME_ABUSE = "param_name_abuse"
    ANSI_INJECTION = "ansi_injection"
    DESERIALIZATION = "deserialization"
    AUTO_APPROVE = "auto_approve"
    META = "meta"  # scan-itself failures, inconclusive outcomes


class Evidence(BaseModel):
    """Concrete proof for a finding — where it is, verbatim snippet, context."""

    location: str = Field(description="E.g., 'tools[getFile].description' or 'src/foo.py:42'")
    snippet: str | None = Field(default=None, description="Verbatim excerpt, truncated if huge.")
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str = Field(description="Stable mception rule ID, e.g. MCP-TP-001.")
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    description: str = Field(description="What's wrong and why it matters.")
    remediation: str = Field(description="Actionable fix guidance.")
    evidence: list[Evidence] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list, description="CWE IDs like 'CWE-78'.")
    owasp_mcp: str | None = Field(
        default=None, description="OWASP MCP Top 10 entry, e.g. 'MCP01:2025'."
    )
    references: list[str] = Field(default_factory=list, description="URLs.")
    target_component: str | None = Field(
        default=None, description="Which tool/resource/file this applies to, if scoped."
    )
