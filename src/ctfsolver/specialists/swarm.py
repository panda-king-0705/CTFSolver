"""Multi-model racing (the ctf-agent swarm) + a coordinator.

When the specialists come up empty, don't bet on one model — race several on the WHOLE
challenge in parallel, each in its own disposable sandbox, and take the first flag. This is
still whole-challenge solving (no fragmentation): every racer owns the entire challenge; they
just attack it with different models, and the fastest-correct wins.

A **coordinator** turns a losing wave into the next wave's edge: it reads every racer's
transcript and writes one paragraph of tactical guidance, fed to all racers as a shared hint.
That's ctf-agent's "coordinator reads solver traces, crafts targeted guidance" and its
cross-solver insight sharing, in one place.

Injectable by design (a `spawn(model) -> SolveContext` callable and a `coordinator` async fn),
so it tests offline with fake models and no real sandboxes-at-scale. Needs real models to do
anything useful; the orchestrator only reaches here when a real model is configured.
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

from ..llm.base import Message
from ..trace import Trace
from .agent_loop import agentic_solve
from .base import SolveContext

SpawnFn = Callable[[str], SolveContext]           # model -> a fresh, staged, pinned context
CoordinatorFn = Callable[[list[str]], Awaitable[Optional[str]]]


async def _race_one(spawn: SpawnFn, model: str, max_iters: int, hint: Optional[str]):
    """One racer: a fresh sandbox + context pinned to `model`, run the agentic loop."""
    ctx = spawn(model)
    try:
        flag, steps = await agentic_solve(ctx, stage="solve_strategy",
                                          max_iters=max_iters, hint=hint)
        return model, flag, steps
    finally:
        try:
            ctx.sandbox.close()  # disposable: closed even if this racer is cancelled
        except Exception:
            pass


async def _wave(spawn: SpawnFn, models: list[str], trace: Trace,
                max_iters: int, hint: Optional[str]) -> tuple[Optional[str], list[str]]:
    """Run all models concurrently; return the first flag and cancel the stragglers."""
    tasks = {asyncio.ensure_future(_race_one(spawn, m, max_iters, hint)): m for m in models}
    pending = set(tasks)
    steps: list[str] = []
    winner: Optional[str] = None
    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                m = tasks[t]
                try:
                    model, flag, rsteps = t.result()
                except asyncio.CancelledError:
                    continue
                except Exception as exc:
                    steps.append(f"[{m}] racer error: {exc}")
                    continue
                steps.extend(f"[{model}] {s}" for s in rsteps[-3:])
                if flag:
                    winner = flag
                    steps.append(f"swarm winner: {model} found the flag")
                    trace.note("solve", f"swarm winner: {model}")
                    return winner, steps
    finally:
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    return None, steps


async def swarm_solve(spawn: SpawnFn, models: list[str], *, trace: Trace,
                      coordinator: Optional[CoordinatorFn] = None, waves: int = 1,
                      max_iters: int = 6) -> tuple[Optional[str], list[str]]:
    """Race `models` on the whole challenge; the first flag wins. With waves>1 and a
    coordinator, a losing wave is summarized into guidance for the next. Returns (flag, steps)."""
    if not models:
        return None, ["swarm: no models configured"]
    all_steps = [f"swarm: racing {len(models)} model(s): {', '.join(models)}"]
    trace.note("solve", f"swarm: racing {len(models)} models")
    hint: Optional[str] = None

    for w in range(max(1, waves)):
        flag, steps = await _wave(spawn, models, trace, max_iters, hint)
        all_steps.extend(steps)
        if flag:
            return flag, all_steps
        if coordinator and w < waves - 1:
            try:
                hint = await coordinator(steps)
            except Exception as exc:
                hint = None
                all_steps.append(f"coordinator error: {exc}")
            if hint:
                all_steps.append(f"coordinator guidance for wave {w + 2}: {hint[:160]}")
                trace.note("solve", f"coordinator guidance: {hint[:120]}")

    return None, all_steps


_COORD_SYS = (
    "You are a world-class CTF competition coordinator. Several solver models just attacked a "
    "challenge and none found the flag. Read their transcripts and write ONE short paragraph of "
    "concrete tactical guidance for the next attempt: the most likely vulnerability/approach, "
    "the specific next thing to try, and what to stop wasting time on. Be specific, not generic."
)


def make_coordinator(client, trace: Trace) -> CoordinatorFn:
    """A coordinator backed by `client` (a frontier model). No-ops on the stub."""
    async def coordinate(wave_steps: list[str]) -> Optional[str]:
        if str(getattr(client, "model", "")).startswith("stub:"):
            return None
        prompt = ("Transcripts from the losing wave:\n" + "\n".join(wave_steps[-50:])
                  + "\n\nYour tactical guidance (one paragraph):")
        try:
            resp = await client.complete([Message("user", prompt)], system=_COORD_SYS,
                                         max_tokens=320)
        except Exception:
            return None
        return (resp.text or "").strip()[:800] or None
    return coordinate
