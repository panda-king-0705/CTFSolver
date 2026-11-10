"""Budget ledger with reservations, so a run can never silently overspend.

Mirrors the Brain's reservation ledger: before every billable action the caller asks
`can_afford`; after it completes the caller `charge`s the actual cost. The ledger
tracks USD, tool-call count and wall-clock against the challenge's Budget caps.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..models import Budget


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Ledger:
    budget: Budget
    spent_usd: float = 0.0
    tool_calls: int = 0
    started_at: float = field(default_factory=time.time)

    def time_left(self) -> float:
        return max(0.0, self.budget.wall_seconds - (time.time() - self.started_at))

    def usd_left(self) -> float:
        return max(0.0, self.budget.usd - self.spent_usd)

    def calls_left(self) -> int:
        return max(0, self.budget.tool_calls - self.tool_calls)

    def can_afford(self, usd: float = 0.0, calls: int = 1) -> bool:
        return (
            self.spent_usd + usd <= self.budget.usd + 1e-9
            and self.tool_calls + calls <= self.budget.tool_calls
            and self.time_left() > 0
        )

    def charge(self, usd: float = 0.0, calls: int = 1, *, what: str = "") -> None:
        if not self.can_afford(usd, calls):
            raise BudgetExceeded(
                f"budget exceeded on {what or 'action'}: "
                f"usd {self.spent_usd:.4f}+{usd:.4f}/{self.budget.usd}, "
                f"calls {self.tool_calls}+{calls}/{self.budget.tool_calls}, "
                f"time_left {self.time_left():.0f}s"
            )
        self.spent_usd += usd
        self.tool_calls += calls

    def snapshot(self) -> dict:
        return {
            "spent_usd": round(self.spent_usd, 4),
            "usd_left": round(self.usd_left(), 4),
            "tool_calls": self.tool_calls,
            "calls_left": self.calls_left(),
            "time_left_s": round(self.time_left(), 1),
        }

    @property
    def pressure(self) -> float:
        """0..1 scarcity signal the orchestrator uses to favour cheaper approaches."""
        usd_p = self.spent_usd / self.budget.usd if self.budget.usd else 1.0
        call_p = self.tool_calls / self.budget.tool_calls if self.budget.tool_calls else 1.0
        time_p = 1.0 - (self.time_left() / self.budget.wall_seconds if self.budget.wall_seconds else 0.0)
        return max(usd_p, call_p, time_p)
