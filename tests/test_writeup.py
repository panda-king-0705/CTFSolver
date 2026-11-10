"""Writeup generation: core sections, unsolved attempt logs, reproducible solver capture
from the trace, and that the orchestrator attaches a writeup to every report."""
from __future__ import annotations

import asyncio

from ctfsolver.models import (
    Artifact,
    Category,
    Challenge,
    Flag,
    Outcome,
    OutcomeStatus,
    Target,
    Understanding,
)
from ctfsolver.pipeline.writeup import build_writeup, generate_writeup
from ctfsolver.trace import Trace


def _solved_case():
    chal = Challenge(
        name="toy-xor", points=100, flag_format=r"flag\{[^}]+\}",
        description="A warm-up.", artifacts=[Artifact(path="cipher.txt", name="cipher.txt", kind="text")],
    )
    u = Understanding(category=Category.CRYPTO, subtype="encoding",
                      recon=["cipher.txt: text", "looks base64-encoded"],
                      candidate_techniques=["Single-byte XOR brute force"])
    o = Outcome(OutcomeStatus.SOLVED, flag=Flag("flag{won}", source="xor(0x5c) of cipher.txt", verified=True),
                steps=["read cipher.txt", "single-byte XOR key=0x5c -> flag"],
                specialist="crypto-specialist")
    return chal, u, o


def test_writeup_core_sections():
    chal, u, o = _solved_case()
    md = build_writeup(chal, u, o, {"spent_usd": 0.0, "tool_calls": 1})
    assert "# toy-xor — crypto (100 pts)" in md
    assert "`flag{won}`" in md and "verified" in md
    assert "## Summary" in md
    assert "## Approach" in md and "single-byte XOR key=0x5c -> flag" in md
    assert "## Technique" in md and "Single-byte XOR brute force" in md
    assert md.rstrip().endswith("UTC*")


def test_writeup_unsolved_attempt_log():
    chal = Challenge(name="hardpwn", flag_format=r"flag\{[^}]+\}")
    u = Understanding(category=Category.PWN)
    o = Outcome(OutcomeStatus.BLOCKED, notes="needs the container sandbox",
                steps=["checksec -> NX"], specialist="pwn-specialist",
                hint_request="enable the container sandbox")
    md = build_writeup(chal, u, o)
    assert "Attempt log" in md
    assert "not recovered" in md and "blocked" in md
    assert "## Still blocked on" in md and "enable the container sandbox" in md


def test_writeup_captures_solver_and_commands_from_trace():
    chal, u, o = _solved_case()
    tr = Trace(chal.id)
    tr.emit("solve", "script", "solve.py", lang="python3", source="print('flag{won}')")
    tr.cmd("solve", "python3 solve.py cipher.txt", rc=0)
    md = build_writeup(chal, u, o, trace=tr)
    assert "## Solver" in md and "solve.py" in md and "print('flag{won}')" in md
    assert "## Commands" in md and "python3 solve.py cipher.txt" in md


def test_generate_writeup_template_when_no_llm():
    chal, u, o = _solved_case()
    md = asyncio.run(generate_writeup(chal, u, o, {"spent_usd": 0.0}, llm=None))
    assert "## Approach" in md and "`flag{won}`" in md


def test_orchestrator_attaches_writeup():
    import json
    import os

    from ctfsolver.memory.store import MemoryStore
    from ctfsolver.models import Budget
    from ctfsolver.orchestrator import Orchestrator
    from ctfsolver.pipeline.intake import intake_from_spec

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "examples", "toy_xor", "challenge.json")) as f:
        spec = json.load(f)
    spec["_base"] = os.path.join(root, "examples", "toy_xor")
    chal = intake_from_spec(spec)
    rep = asyncio.run(Orchestrator(memory=MemoryStore(":memory:")).solve_challenge(chal, Budget(usd=2.0)))
    assert rep.writeup and "# toy-xor" in rep.writeup
    assert rep.outcome.flag.value in rep.writeup
