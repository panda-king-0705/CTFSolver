"""Specialists: each owns a whole challenge end to end inside its sandbox."""
from __future__ import annotations

from .base import SolveContext, Specialist  # noqa: F401
from .registry import all_specialists, get, load_defaults, register  # noqa: F401

__all__ = ["SolveContext", "Specialist", "register", "get", "all_specialists", "load_defaults"]
