"""Sandboxes: the confined environment a specialist works inside.

- LocalSandbox       : offline, read-only tool allow-list, no real egress (CI/dev)
- ContainerSandbox   : disposable container, egress confined to the target (production)
- egress             : the network-layer scope policy both agree on
"""
from __future__ import annotations

from .base import ExecResult, Sandbox  # noqa: F401
from .container import ContainerSandbox  # noqa: F401
from .driver import ContainerDriver, DockerDriver, LocalProcessDriver, SandboxLimits  # noqa: F401
from .egress import ANY_PORT, EgressRule, EgressRuleset, ruleset_from_scope  # noqa: F401
from .factory import SandboxFactory, auto_sandbox_factory  # noqa: F401
from .local import SAFE_BINS, LocalSandbox  # noqa: F401

__all__ = [
    "ExecResult", "Sandbox", "LocalSandbox", "SAFE_BINS",
    "ContainerSandbox", "ContainerDriver", "DockerDriver", "LocalProcessDriver",
    "SandboxLimits", "EgressRule", "EgressRuleset", "ruleset_from_scope", "ANY_PORT",
    "SandboxFactory", "auto_sandbox_factory",
]
