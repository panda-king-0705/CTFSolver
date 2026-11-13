"""Multi-model racing + coordinator. Offline with injectable fake spawns/models — first flag
wins, stragglers are cancelled, and a losing wave is guided into the next."""
from __future__ import annotations

import asyncio
import json

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopePolicy
from ctfsolver.llm.base import LLMResponse
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Category, Challenge, Understanding
from ctfsolver.sandbox.local import LocalSandbox
from ctfsolver.specialists.base import SolveContext
from ctfsolver.specialists.swarm import swarm_solve
from ctfsolver.trace import Trace


class FakeModel:
    def __init__(self, actions, model="fake:frontier"):
        self.model = model
        self._a = [json.dumps(a) for a in actions]
        self.calls = 0

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2):
        a = self._a[min(self.calls, len(self._a) - 1)]
        self.calls += 1
        return LLMResponse(text=a, cost_usd=0.001, input_tokens=5, output_tokens=5, model=self.model)


def _spawn_for(action_for):
    """Build a spawn(model) that makes a fresh sandbox (flag staged) + a FakeModel per model."""
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC)

    def spawn(model):
        sbx = LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget(usd=2.0)), AuditLog())
        sbx.write_bytes("flag.txt", b"flag{swarm_pulled_it}\n")
        client = FakeModel(action_for(model))
        return SolveContext(
            challenge=chal, understanding=Understanding(category=chal.category_hint),
            sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
            settings=None, ledger=sbx.ledger, techniques=[], _llm_factory=lambda s: client,
        )
    return spawn


def test_first_flag_wins_the_race():
    def action_for(model):
        if model == "winner":
            return [{"tool": "python", "input": "print(open('flag.txt').read())"}]
        return [{"tool": "shell", "input": "echo nope"}]  # losers spin (and get refused locally)
    flag, steps = asyncio.run(swarm_solve(
        _spawn_for(action_for), ["loser1", "winner", "loser2"], trace=Trace("t"), waves=1))
    assert flag == "flag{swarm_pulled_it}", steps
    assert any("swarm winner: winner" in s for s in steps)


def test_empty_swarm_is_a_noop():
    flag, steps = asyncio.run(swarm_solve(lambda m: None, [], trace=Trace("t")))
    assert flag is None and any("no models" in s for s in steps)


def test_coordinator_guides_the_next_wave():
    calls = {"n": 0}

    def action_for(model):
        # fresh FakeModel each spawn; wave 1 spin, wave 2 (2nd spawn) solves
        calls["n"] += 1
        if calls["n"] == 1:
            return [{"tool": "shell", "input": "echo nope"}]
        return [{"tool": "python", "input": "print(open('flag.txt').read())"}]

    coord_called = {"n": 0}

    async def coordinator(steps):
        coord_called["n"] += 1
        return "read flag.txt directly with python"

    flag, steps = asyncio.run(swarm_solve(
        _spawn_for(action_for), ["m1"], trace=Trace("t"),
        coordinator=coordinator, waves=2))
    assert flag == "flag{swarm_pulled_it}", steps
    assert coord_called["n"] == 1
    assert any("coordinator guidance for wave 2" in s for s in steps)
