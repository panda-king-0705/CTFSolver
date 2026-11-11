"""Metacognition: the brain's Cognitive Control -> Candidate Solutions and Confidence ->
Early-Stop / Reflection, mapped to CTF (flag-as-oracle, so no subjective quality gates).

Instead of one agentic pass, the solver tries candidate approaches cheap-first and only
escalates to the frontier model when it's worth it:

  - Low Effort  -> the specialists' deterministic recon + memory (already ran before this).
  - Low Cost    -> the agentic loop on the STANDARD tier, a few steps.
  - High Cost   -> the agentic loop on the FRONTIER tier, more steps, carrying a fresh idea.

Between candidates it REFLECTS: a short, honest self-assessment {confidence, blocker,
next_idea}. If the challenge is blocked on something only the operator can provide (a missing
handout, credentials, the binary) and confidence is low, it EARLY-STOPS with that reason
instead of burning the frontier budget. Otherwise it carries the next idea forward.

Needs a real model; no-ops cleanly on the offline stub.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..llm.base import Message, extract_json
from .agent_loop import _context, agentic_solve, is_stub
from .base import SolveContext


@dataclass
class Candidate:
    name: str
    stage: str      # -> model tier via settings.model_for
    max_iters: int
    min_cost: float  # don't start it without at least this much budget


def _candidates(points: int) -> list[Candidate]:
    """Economic choice: always try the cheap candidate; only spend the frontier model on a
    challenge worth it (higher points) -- points-per-effort, the brain's Economic Concepts."""
    cands = [Candidate("low-cost", "solve_scripting", 4, 0.02)]
    if points >= 30:
        cands.append(Candidate("high-cost", "solve_strategy", 8, 0.05))
    return cands


_REFLECT_SYS = (
    "You are a CTF solver reflecting on a failed attempt. Be brutally honest. Respond with "
    "STRICT JSON only: {\"confidence\": <0.0-1.0 that the flag is reachable by trying harder "
    "in the sandbox>, \"blocker\": \"<the ONE thing only the operator can provide (a missing "
    "handout file, credentials, the binary, a URL) -- or null if nothing is blocking>\", "
    "\"next_idea\": \"<one concrete, DIFFERENT approach to try next>\"}"
)


async def _reflect(ctx: SolveContext, attempt_steps: list[str]) -> Optional[dict]:
    """One cheap self-assessment call. Returns the parsed dict, or None if unavailable."""
    try:
        client = ctx.llm("triage_analysis")  # standard tier; cheap-ish
    except Exception:
        return None
    if str(getattr(client, "model", "")).startswith("stub:"):
        return None
    if not ctx.ledger.can_afford(0.01, 1):
        return None
    prompt = (_context(ctx) + "\n\nWhat was tried (most recent):\n"
              + "\n".join(attempt_steps[-12:]) + "\n\nReflect (JSON only):")
    try:
        resp = await client.complete([Message("user", prompt)], system=_REFLECT_SYS, max_tokens=300)
        data = extract_json(resp.text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _is_real_blocker(blocker) -> bool:
    if not blocker:
        return False
    s = str(blocker).strip().lower()
    return s not in ("", "null", "none", "n/a", "nothing", "no blocker", "false")


async def metacognitive_solve(ctx: SolveContext, *, points: int = 100
                              ) -> tuple[Optional[str], list[str]]:
    """Run candidate approaches cheap-first with reflection + early-stop between them.
    Returns (flag | None, steps)."""
    steps: list[str] = []
    if is_stub(ctx, "solve_strategy") and is_stub(ctx, "solve_scripting"):
        steps.append("metacognition skipped: needs a real model "
                     "(run with --subscription or an API key)")
        return None, steps

    ctx.trace.note("solve", "no specialist flag — metacognition: candidate selection")
    hint: Optional[str] = None
    candidates = _candidates(points)

    for i, cand in enumerate(candidates):
        if not ctx.ledger.can_afford(cand.min_cost, 1):
            steps.append(f"skip candidate {cand.name}: out of budget")
            break
        ctx.trace.note("solve", f"candidate {cand.name} ({cand.stage}, ≤{cand.max_iters} steps)"
                       + (f" — idea: {hint}" if hint else ""))
        steps.append(f"candidate: {cand.name} ({cand.stage}, ≤{cand.max_iters} steps)")
        flag, asteps = await agentic_solve(ctx, stage=cand.stage,
                                           max_iters=cand.max_iters, hint=hint)
        steps.extend(asteps)
        if flag:
            steps.append(f"solved on the {cand.name} candidate")
            return flag, steps

        # reflect before spending more (confidence -> early stop / next idea)
        last = i == len(candidates) - 1
        reflection = await _reflect(ctx, asteps)
        if reflection is not None:
            conf = reflection.get("confidence")
            blocker = reflection.get("blocker")
            idea = reflection.get("next_idea")
            ctx.trace.note("solve", f"reflection: confidence={conf} blocker={blocker}")
            steps.append(f"reflection after {cand.name}: confidence={conf}, "
                         f"blocker={blocker if _is_real_blocker(blocker) else 'none'}")
            try:
                low_conf = conf is None or float(conf) < 0.35
            except (TypeError, ValueError):
                low_conf = True
            if _is_real_blocker(blocker) and low_conf:
                steps.append(f"early stop: blocked on {blocker} — only the operator can "
                             "provide this; not spending more budget")
                return None, steps
            hint = idea or hint
        if last:
            break

    return None, steps
