"""The agentic fallback: when no specialist has a canned path, the model drives a bounded
think -> act -> observe loop in the sandbox instead of giving up. Tested offline with a
scripted fake model (no network); also checks the stub no-ops and that repeated actions are
loop-detected rather than re-run forever."""
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
from ctfsolver.specialists.agent_loop import agentic_solve
from ctfsolver.specialists.base import SolveContext
from ctfsolver.trace import Trace


class FakeModel:
    """A scripted model: returns queued JSON actions, then repeats the last one."""

    def __init__(self, actions, model="fake:frontier"):
        self.model = model
        self._actions = [json.dumps(a) for a in actions]
        self.calls = 0

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2):
        a = self._actions[min(self.calls, len(self._actions) - 1)]
        self.calls += 1
        return LLMResponse(text=a, cost_usd=0.001, input_tokens=10, output_tokens=10, model=self.model)


def _ctx(chal, sbx, client):
    return SolveContext(
        challenge=chal, understanding=Understanding(category=chal.category_hint),
        sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
        settings=None, ledger=sbx.ledger, techniques=[],
        _llm_factory=lambda stage: client,
    )


def _sbx(chal):
    return LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget(usd=1.0)), AuditLog())


def test_agent_loop_reasons_to_the_flag():
    chal = Challenge(name="mystery", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC)
    sbx = _sbx(chal)
    sbx.write_bytes("secret.txt", b"nothing... flag{agent_reasoned_it_out} ...here\n")
    client = FakeModel([{"thought": "read the file with python",
                         "tool": "python", "input": "print(open('secret.txt').read())"}])
    try:
        flag, steps = asyncio.run(agentic_solve(_ctx(chal, sbx, client)))
        assert flag == "flag{agent_reasoned_it_out}", steps
        assert any("recovered the flag" in s for s in steps)
    finally:
        sbx.close()


def test_agent_loop_submit_path():
    chal = Challenge(name="q", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC)
    sbx = _sbx(chal)
    client = FakeModel([{"thought": "I know it", "tool": "submit", "flag": "flag{submitted}"}])
    try:
        flag, _ = asyncio.run(agentic_solve(_ctx(chal, sbx, client)))
        assert flag == "flag{submitted}"
    finally:
        sbx.close()


def test_agent_loop_noops_on_stub():
    chal = Challenge(name="q", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC)
    sbx = _sbx(chal)
    try:
        flag, steps = asyncio.run(agentic_solve(_ctx(chal, sbx, StubClient("frontier"))))
        assert flag is None
        assert any("needs a real model" in s for s in steps)
    finally:
        sbx.close()


def test_agent_loop_detects_repetition_and_stops():
    chal = Challenge(name="q", flag_format=r"flag\{[^}]+\}", category_hint=Category.MISC)
    sbx = _sbx(chal)
    # always proposes the same useless command -> must be detected and bounded, not infinite
    client = FakeModel([{"thought": "spin", "tool": "shell", "input": "echo nope"}])
    try:
        flag, steps = asyncio.run(agentic_solve(_ctx(chal, sbx, client), max_iters=6))
        assert flag is None
        assert client.calls <= 6  # bounded by max_iters
    finally:
        sbx.close()
