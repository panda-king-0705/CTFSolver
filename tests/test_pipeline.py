"""Pipeline stages: triage classification, whole-challenge routing, flag verification."""
from __future__ import annotations

import asyncio
import os

from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Category, Challenge, Flag, Submission, Target
from ctfsolver.pipeline.intake import intake_from_spec
from ctfsolver.pipeline.route import route
from ctfsolver.pipeline.triage import triage
from ctfsolver.pipeline.verify import verify
from ctfsolver.specialists.registry import load_defaults
from ctfsolver.trace import Trace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOY = os.path.join(ROOT, "examples", "toy_xor", "challenge.json")


def _toy_challenge() -> Challenge:
    import json

    with open(TOY) as f:
        spec = json.load(f)
    spec["_base"] = os.path.dirname(TOY)
    return intake_from_spec(spec)


def test_triage_classifies_crypto():
    load_defaults()
    chal = _toy_challenge()
    u = asyncio.run(triage(chal, MemoryStore(":memory:"), Trace(chal.id)))
    assert u.category is Category.CRYPTO
    assert u.score > 0.5


def test_route_whole_handoff_to_specialist():
    load_defaults()
    chal = _toy_challenge()
    u = asyncio.run(triage(chal, MemoryStore(":memory:"), Trace(chal.id)))
    decision = route(chal, u)
    assert decision.specialist is not None
    assert decision.specialist.category is Category.CRYPTO
    assert "whole-challenge hand-off" in decision.rationale


def test_verify_empty_done_guard_and_format():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    tr = Trace(chal.id)
    accepted, rec = asyncio.run(verify(None, chal, tr))
    assert not accepted and rec["reason"] == "no flag"
    accepted, rec = asyncio.run(verify(Flag("not-a-flag"), chal, tr))
    assert not accepted and rec["reason"] == "format mismatch"


def test_verify_regex_checker_exact_answer():
    chal = Challenge(
        name="c", flag_format=r"flag\{[^}]+\}",
        submission=Submission(kind="regex", extra={"answer": "flag{right}"}),
    )
    tr = Trace(chal.id)
    ok, _ = asyncio.run(verify(Flag("flag{right}"), chal, tr))
    assert ok
    bad, _ = asyncio.run(verify(Flag("flag{wrong}"), chal, tr))
    assert not bad  # matches format but not the checker's answer
