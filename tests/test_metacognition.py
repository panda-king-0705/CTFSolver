"""Metacognition: candidate selection (cheap-then-dear) with reflection and early-stop.
Offline with scripted fake models per stage -- no network."""
from __future__ import annotations

import asyncio
import json

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopePolicy
from ctfsolver.llm.base import LLMResponse
from ctfsolver.llm.stub import StubClient
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Category, Challenge, Understanding
from ctfsolver.sandbox.local import LocalSandbox
from ctfsolver.specialists.base import SolveContext
from ctfsolver.specialists.metacognition import metacognitive_solve
from ctfsolver.trace import Trace


class FakeModel:
    def __init__(self, actions, model="fake:x"):
        self.model = model
        self._a = [json.dumps(a) for a in actions]
        self.calls = 0

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2):
        a = self._a[min(self.calls, len(self._a) - 1)]
        self.calls += 1
        return LLMResponse(text=a, cost_usd=0.001, input_tokens=5, output_tokens=5, model=self.model)


def _ctx(chal, sbx, clients):
    return SolveContext(
        challenge=chal, understanding=Understanding(category=chal.category_hint),
        sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
        settings=None, ledger=sbx.ledger, techniques=[],
        _llm_factory=lambda stage: clients.get(stage, clients["_default"]),
    )


def _sbx(chal):
    return LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget(usd=2.0)), AuditLog())


def test_escalates_from_cheap_to_frontier_and_solves():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC, points=100)
    sbx = _sbx(chal)
    sbx.write_bytes("f.txt", b"flag{frontier_candidate_got_it}\n")
    low = FakeModel([{"tool": "shell", "input": "echo nope"}], "fake:standard")
    reflect = FakeModel([{"confidence": 0.6, "blocker": None, "next_idea": "read f.txt"}], "fake:standard")
    high = FakeModel([{"tool": "python", "input": "print(open('f.txt').read())"}], "fake:frontier")
    clients = {"solve_scripting": low, "triage_analysis": reflect, "solve_strategy": high, "_default": high}
    try:
        flag, steps = asyncio.run(metacognitive_solve(_ctx(chal, sbx, clients), points=100))
        assert flag == "flag{frontier_candidate_got_it}", steps
        assert low.calls >= 1 and high.calls >= 1   # tried cheap first, then escalated
        assert any("candidate: high-cost" in s for s in steps)
    finally:
        sbx.close()


def test_early_stop_on_real_blocker_skips_frontier():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}", category_hint=Category.PWN, points=100)
    sbx = _sbx(chal)
    low = FakeModel([{"tool": "shell", "input": "echo nope"}], "fake:standard")
    reflect = FakeModel([{"confidence": 0.1, "blocker": "the vulnerable binary was not provided",
                          "next_idea": "need the binary"}], "fake:standard")
    high = FakeModel([{"tool": "python", "input": "print('should not run')"}], "fake:frontier")
    clients = {"solve_scripting": low, "triage_analysis": reflect, "solve_strategy": high, "_default": high}
    try:
        flag, steps = asyncio.run(metacognitive_solve(_ctx(chal, sbx, clients), points=100))
        assert flag is None
        assert high.calls == 0  # early-stopped before spending the frontier model
        assert any("early stop" in s and "binary" in s for s in steps)
    finally:
        sbx.close()


def test_noops_on_stub():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC, points=100)
    sbx = _sbx(chal)
    stub = StubClient("frontier")
    clients = {"_default": stub}
    try:
        flag, steps = asyncio.run(metacognitive_solve(_ctx(chal, sbx, clients), points=100))
        assert flag is None
        assert any("needs a real model" in s for s in steps)
    finally:
        sbx.close()
