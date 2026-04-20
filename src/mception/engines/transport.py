"""Transport / auth engine — runs transport_rules across the workdir."""

from __future__ import annotations

from ..rules.transport_rules import (
    rule_bind_all_interfaces,
    rule_remote_transport_no_auth,
    rule_weak_transport_config,
)
from .base import EngineResult, TargetContext


class TransportEngine:
    name = "transport"

    async def run(self, target_ctx: TargetContext) -> EngineResult:
        r = EngineResult(engine=self.name)
        if target_ctx.workdir is None:
            r.inconclusive = True
            return r
        r.findings.extend(rule_remote_transport_no_auth(target_ctx.workdir))
        r.findings.extend(rule_bind_all_interfaces(target_ctx.workdir))
        r.findings.extend(rule_weak_transport_config(target_ctx.workdir))
        return r
