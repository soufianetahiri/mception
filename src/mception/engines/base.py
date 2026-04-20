"""Engine interface. Concrete engines live in metadata.py, sast.py, sca.py, …"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..findings import Finding


@dataclass
class EngineResult:
    engine: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    inconclusive: bool = False


class Engine(Protocol):
    name: str

    async def run(self, target_ctx: "TargetContext") -> EngineResult:  # noqa: F821
        ...


@dataclass
class TargetContext:
    """What engines receive. Filled in progressively by the fetcher + metadata engine."""

    target_ref: str
    target_kind: str  # "local" | "npm" | "pypi" | "git" | "docker" | "config"
    workdir: "Path | None" = None  # noqa: F821
    introspection: dict | None = None  # Result of MCP client introspection (tools/resources/prompts)
    manifest: dict | None = None  # package.json / pyproject.toml / dockerfile contents
