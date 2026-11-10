"""ctfsolver — an autonomous CTF solver built on the BrainEngine design.

The guiding correction (from AgentCo's traced live runs): the brain is strong at
orchestration and weak at splitting tightly-coupled work across agents that cannot
run code. Exploitation is maximally coupled, so the orchestrator decides, budgets,
routes, verifies and remembers -- but every challenge is handed *whole* to a single
specialist with a real sandbox. The orchestrator never fragments the exploit.

Public surface is intentionally small; import submodules directly for the rest.
"""
from __future__ import annotations

__version__ = "0.1.0"

from .models import (  # noqa: F401
    Category,
    Target,
    Artifact,
    Challenge,
    Understanding,
    Flag,
    Attempt,
    Outcome,
    OutcomeStatus,
    Budget,
    Technique,
)

__all__ = [
    "Category",
    "Target",
    "Artifact",
    "Challenge",
    "Understanding",
    "Flag",
    "Attempt",
    "Outcome",
    "OutcomeStatus",
    "Budget",
    "Technique",
    "__version__",
]
