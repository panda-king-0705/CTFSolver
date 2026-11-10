"""Eval harness: run the solver over a challenge set and measure it."""
from __future__ import annotations

from .harness import (  # noqa: F401
    ChallengeResult,
    EvalReport,
    load_suite,
    render_markdown,
    run_eval,
)

__all__ = ["ChallengeResult", "EvalReport", "load_suite", "render_markdown", "run_eval"]
