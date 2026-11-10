"""End-to-end: a challenge goes in, a verified flag comes out -- fully offline."""
from __future__ import annotations

import asyncio
import json
import os

from ctfsolver.memory.seed import seed_techniques
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Category
from ctfsolver.orchestrator import Orchestrator
from ctfsolver.pipeline.intake import intake, intake_from_spec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOY = os.path.join(ROOT, "examples", "toy_xor", "challenge.json")
EXPECTED = "flag{x0r_4nd_base64_are_not_crypto}"


def _toy():
    with open(TOY) as f:
        spec = json.load(f)
    spec["_base"] = os.path.dirname(TOY)
    return intake_from_spec(spec)


def _orchestrator() -> Orchestrator:
    mem = MemoryStore(":memory:")
    seed_techniques(mem)
    return Orchestrator(memory=mem)


def test_toy_challenge_solved_and_verified():
    orch = _orchestrator()
    rep = asyncio.run(orch.solve_challenge(_toy(), Budget(usd=2.0)))
    o = rep.outcome
    assert o.solved, f"expected solve, got {o.status} ({o.notes})"
    assert o.flag.value == EXPECTED
    assert o.flag.verified is True
    assert o.specialist == "crypto-specialist"


def test_e2e_walks_the_whole_diagram():
    orch = _orchestrator()
    rep = asyncio.run(orch.solve_challenge(_toy(), Budget(usd=2.0)))
    blocks = rep.trace.blocks_touched()
    for expected in ("orchestrate", "triage", "route", "verify", "learn"):
        assert expected in blocks, f"missing block {expected}: {blocks}"
    assert any(b.startswith("solve:") for b in blocks)
    # budget was metered
    assert rep.ledger_snapshot["tool_calls"] >= 0
    assert rep.ledger_snapshot["spent_usd"] >= 0


def test_learning_banks_a_technique_on_win():
    mem = MemoryStore(":memory:")
    orch = Orchestrator(memory=mem)
    before = len(mem.recall_techniques("", category=Category.CRYPTO, limit=999))
    asyncio.run(orch.solve_challenge(_toy(), Budget(usd=2.0)))
    after = len(mem.recall_techniques("", category=Category.CRYPTO, limit=999))
    assert after > before  # a solve bankrolls a procedural lesson
    # and an episode was recorded
    assert mem.recent_episodes(5)


def test_blocked_challenge_surfaces_cleanly():
    # a web challenge with only a remote target -> web specialist blocks for the
    # container sandbox (and must not falsely claim a flag)
    orch = _orchestrator()
    chal = intake("webby", targets=["https://authorized.ctf/"])
    rep = asyncio.run(orch.solve_challenge(chal, Budget(usd=1.0)))
    assert not rep.outcome.solved
    assert rep.outcome.flag is None


def test_concurrent_run_prioritizes_and_solves():
    orch = _orchestrator()
    toy = _toy()
    trivial = intake("freebie", files=[])
    trivial.description = "here it is: flag{free_points}"
    trivial.points = 50
    results = asyncio.run(orch.run([(toy, Budget(usd=2.0)), (trivial, Budget(usd=1.0))]))
    assert len(results) == 2
    assert results[toy.id].outcome.solved
    assert results[trivial.id].outcome.solved  # misc finds it in the description
