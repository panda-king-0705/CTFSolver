"""Route: hand the WHOLE challenge to the single best-fit specialist. This is the
architecture's core choice -- never split tightly-coupled work. Fit is category match
first, with the specialist's own `fit_bonus` and a recalled-technique nudge as
tie-breakers. A cross-category challenge is re-routed whole by the orchestrator when the
specialist returns WAITING with `reroute_to`."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import Category, Challenge, Understanding
from ..specialists.base import Specialist
from ..specialists.registry import all_specialists, get


@dataclass
class RouteDecision:
    category: Category
    specialist: Optional[Specialist]
    fit: float
    rationale: str


def route(challenge: Challenge, understanding: Understanding) -> RouteDecision:
    cat = understanding.category
    best: Optional[Specialist] = None
    best_fit = -1.0
    for sp in all_specialists().values():
        fit = 0.0
        if sp.category == cat:
            fit += 0.75
        fit += 0.25 * max(0.0, min(1.0, sp.fit_bonus(challenge, understanding)))
        if understanding.candidate_techniques and sp.category == cat:
            fit += 0.10
        if fit > best_fit:
            best_fit, best = fit, sp

    # Fallback: unknown category or nothing matched -> misc owns it.
    if best is None or best_fit <= 0.0:
        best = get(Category.MISC)
        best_fit = 0.3
        cat = Category.MISC

    rationale = (
        f"category={cat.value} fit={round(best_fit, 2)} -> "
        f"{best.name if best else 'none'} (whole-challenge hand-off)"
    )
    return RouteDecision(category=cat, specialist=best, fit=round(best_fit, 2), rationale=rationale)
