"""Guardrails: the layer that makes an exploit-writing agent safe to run.

scope  -- authorized target only (default-deny allow-list)
budget -- reservation ledger, no silent overspend
audit  -- append-only, replayable record of everything that ran
gate   -- human approval for anything out of scope / destructive / sensitive
"""
from __future__ import annotations

from .audit import AuditLog, AuditRecord  # noqa: F401
from .budget import BudgetExceeded, Ledger  # noqa: F401
from .gate import GateDecision, HumanGate, SENSITIVE_ACTIONS  # noqa: F401
from .scope import ScopeError, ScopePolicy  # noqa: F401

__all__ = [
    "AuditLog", "AuditRecord",
    "BudgetExceeded", "Ledger",
    "GateDecision", "HumanGate", "SENSITIVE_ACTIONS",
    "ScopeError", "ScopePolicy",
]
