"""Human gate. Anything out of scope, destructive, or legally sensitive stops for the
operator (the Board) before it runs. In autonomous/CI mode the default approver denies,
so the safe path is the default path."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

# Action kinds that must never run without an explicit human yes.
SENSITIVE_ACTIONS = frozenset(
    {"out_of_scope", "destructive", "exfiltrate", "write_external", "legal_sensitive"}
)


class GateDecision(str, Enum):
    ALLOWED = "allowed"  # not sensitive, proceed
    APPROVED = "approved"  # sensitive, human said yes
    DENIED = "denied"  # sensitive, no approval


Approver = Callable[[str, str], bool]  # (action_kind, detail) -> approved?


def _deny_all(action_kind: str, detail: str) -> bool:
    return False


@dataclass
class HumanGate:
    approver: Approver = field(default=_deny_all)
    enabled: bool = True

    def requires_approval(self, action_kind: str) -> bool:
        return self.enabled and action_kind in SENSITIVE_ACTIONS

    def check(self, action_kind: str, detail: str = "") -> GateDecision:
        if not self.requires_approval(action_kind):
            return GateDecision.ALLOWED
        try:
            ok = bool(self.approver(action_kind, detail))
        except Exception:
            ok = False
        return GateDecision.APPROVED if ok else GateDecision.DENIED
