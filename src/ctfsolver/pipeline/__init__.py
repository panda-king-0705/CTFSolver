"""The six-stage pipeline: intake -> triage -> route -> (solve) -> verify -> (learn).
Solve lives in the specialists; learn lives in the orchestrator's report step."""
from __future__ import annotations

from .checkers import CTFdChecker, HTTPChecker, RCTFChecker, build_checker  # noqa: F401
from .intake import classify_artifact, intake, intake_from_spec, parse_target  # noqa: F401
from .route import RouteDecision, route  # noqa: F401
from .triage import triage  # noqa: F401
from .verify import Checker, RegexChecker, StubChecker, get_checker, verify  # noqa: F401
from .writeup import build_writeup, generate_writeup  # noqa: F401

__all__ = [
    "intake", "intake_from_spec", "parse_target", "classify_artifact",
    "triage", "route", "RouteDecision",
    "verify", "get_checker", "Checker", "StubChecker", "RegexChecker",
    "build_checker", "CTFdChecker", "RCTFChecker", "HTTPChecker",
    "build_writeup", "generate_writeup",
]
