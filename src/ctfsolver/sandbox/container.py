"""ContainerSandbox -- the production execution environment for a specialist.

It runs the specialist's tools inside a disposable container (via a driver), confines
egress to the challenge's target at the network layer (via the egress ruleset), and is
torn down when the challenge ends. It satisfies the exact same `Sandbox` contract as the
offline `LocalSandbox`, so swapping it in changes nothing for the pipeline.

The sandbox workdir is a host directory the driver bind-mounts into the container at
`/work`, so staging files in and reading results back use the base-class file ops
unchanged, and the container sees the same files.
"""
from __future__ import annotations

from typing import Optional

from ..guardrails.audit import AuditLog
from ..guardrails.budget import Ledger
from ..guardrails.gate import HumanGate
from ..guardrails.scope import ScopePolicy
from .base import ExecResult, Sandbox
from .driver import ContainerDriver, LocalProcessDriver, SandboxLimits
from .egress import EgressRuleset, ruleset_from_scope


class ContainerSandbox(Sandbox):
    def __init__(
        self,
        scope: ScopePolicy,
        ledger: Ledger,
        audit: AuditLog,
        *,
        gate: Optional[HumanGate] = None,
        workdir: Optional[str] = None,
        driver: Optional[ContainerDriver] = None,
        limits: Optional[SandboxLimits] = None,
    ) -> None:
        super().__init__(scope, ledger, audit, gate=gate, workdir=workdir)
        self.limits = limits or SandboxLimits()
        self.driver = driver or LocalProcessDriver()
        self.ruleset: EgressRuleset = ruleset_from_scope(scope)
        self._started = False
        self._start()

    def _start(self) -> None:
        self.driver.start(workdir=self.workdir, ruleset=self.ruleset, limits=self.limits)
        self._started = True
        self.audit.record(
            "sandbox", "container_start", self.driver.name,
            egress=self.ruleset.summary(),
            isolation=self.driver.name,
        )

    @property
    def isolated(self) -> bool:
        """Code is isolated from the host only when the driver provides a real container.
        The live specialist paths gate running provided (untrusted) code on this."""
        return getattr(self.driver, "isolated", False)

    async def _run(self, argv: list[str], *, timeout: float) -> ExecResult:
        return await self.driver.exec(argv, timeout=timeout, workdir=self.workdir)

    def close(self) -> None:
        if self._started:
            try:
                self.driver.stop()
            finally:
                self._started = False
                self.audit.record("sandbox", "container_stop", self.driver.name)
        super().close()
