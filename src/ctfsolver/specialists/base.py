"""Specialist contract. A specialist owns a *whole* challenge end to end inside its
sandbox. It never delegates sub-pieces to other agents -- that fragmentation is exactly
what the architecture is built to avoid. If it discovers the challenge truly belongs to
another category, it returns WAITING with `reroute_to`, a clean hand-off of the whole
challenge, not a split.

Fan-out authors: subclass `Specialist`, set `category`, implement `async def solve`.
Everything you need is on the `SolveContext`. Use `self.find_flags(...)` to extract
candidates and `ctx.llm(stage)` for reasoning. Respect the budget via the sandbox
(every exec/egress is already charged); check `ctx.ledger.can_afford(...)` before big
steps and bail to a clean BLOCKED/FAILED rather than spinning.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..config import Settings
from ..guardrails.budget import Ledger
from ..llm.base import LLMClient
from ..memory.store import MemoryStore
from ..models import Category, Challenge, Flag, Outcome, OutcomeStatus, Technique, Understanding
from ..sandbox.base import Sandbox
from ..trace import Trace


@dataclass
class SolveContext:
    """Everything a specialist is handed. Scope, budget and audit already live on the
    sandbox; the ledger is exposed here too for affordability checks."""

    challenge: Challenge
    understanding: Understanding
    sandbox: Sandbox
    memory: MemoryStore
    trace: Trace
    settings: Settings
    ledger: Ledger
    techniques: list[Technique] = field(default_factory=list)
    scratch: dict[str, Any] = field(default_factory=dict)
    _llm_factory: Optional[Callable[[str], LLMClient]] = None

    def llm(self, stage: str) -> LLMClient:
        if self._llm_factory is None:
            raise RuntimeError("no LLM factory bound to this context")
        return self._llm_factory(stage)


class Specialist(ABC):
    category: Category = Category.UNKNOWN
    name: str = "specialist"

    def fit_bonus(self, challenge: Challenge, understanding: Understanding) -> float:
        """Extra routing weight beyond the category match (0..1). Override to claim a
        sub-type you are especially strong at."""
        return 0.0

    @abstractmethod
    async def solve(self, ctx: SolveContext) -> Outcome: ...

    # --- helpers ---------------------------------------------------------- #
    def find_flags(self, text: str, fmt: str) -> list[str]:
        if not text:
            return []
        try:
            return list(dict.fromkeys(re.findall(fmt, text)))
        except re.error:
            return []

    def found(self, value: str, source: str, steps: list[str], **kw: Any) -> Outcome:
        return Outcome(
            status=OutcomeStatus.SOLVED, flag=Flag(value=value, source=source),
            steps=steps, specialist=self.name, **kw,
        )

    def blocked(self, notes: str, steps: list[str], *, hint: Optional[str] = None,
                reroute_to: Optional[Category] = None, **kw: Any) -> Outcome:
        status = OutcomeStatus.WAITING if reroute_to else OutcomeStatus.BLOCKED
        return Outcome(status=status, notes=notes, steps=steps, specialist=self.name,
                       hint_request=hint, reroute_to=reroute_to, **kw)

    def failed(self, notes: str, steps: list[str], **kw: Any) -> Outcome:
        return Outcome(status=OutcomeStatus.FAILED, notes=notes, steps=steps,
                       specialist=self.name, **kw)
