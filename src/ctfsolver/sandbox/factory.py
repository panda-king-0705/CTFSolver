"""Sandbox selection. `auto_sandbox_factory` picks the container sandbox when a Docker
daemon is usable, and falls back to the offline local sandbox otherwise -- so the same
orchestrator code runs fully offline in CI and with real isolation in production."""
from __future__ import annotations

from typing import Callable, Optional

from ..guardrails.audit import AuditLog
from ..guardrails.budget import Ledger
from ..guardrails.gate import HumanGate
from ..guardrails.scope import ScopePolicy
from .base import Sandbox
from .container import ContainerSandbox
from .driver import ContainerDriver, DockerDriver, SandboxLimits
from .local import LocalSandbox

SandboxFactory = Callable[[ScopePolicy, Ledger, AuditLog, HumanGate], Sandbox]


def auto_sandbox_factory(
    *,
    prefer_container: bool = True,
    limits: Optional[SandboxLimits] = None,
    driver: Optional[ContainerDriver] = None,
) -> SandboxFactory:
    """Return a factory the orchestrator can use. Container availability is probed once.
    Pass an explicit `driver` (e.g. LocalProcessDriver) to force the container sandbox
    with a chosen substrate."""
    use_container = prefer_container and (driver is not None or DockerDriver().available())

    def factory(scope: ScopePolicy, ledger: Ledger, audit: AuditLog, gate: HumanGate) -> Sandbox:
        if use_container:
            return ContainerSandbox(
                scope, ledger, audit, gate=gate,
                driver=driver or DockerDriver(), limits=limits,
            )
        return LocalSandbox(scope, ledger, audit, gate=gate)

    return factory
