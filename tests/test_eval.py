"""Eval harness: aggregate metrics, category breakdown, and a run over the example suite."""
from __future__ import annotations

import asyncio
import os

from ctfsolver.eval.harness import (
    ChallengeResult,
    EvalReport,
    load_suite,
    render_markdown,
    run_eval,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE = os.path.join(ROOT, "examples", "suite")


def _report() -> EvalReport:
    rep = EvalReport()
    rep.results = [
        ChallengeResult("a", "crypto", True, 50, 50, "solved", "crypto-specialist", 0.0, 1, 0.1),
        ChallengeResult("b", "crypto", False, 75, 0, "failed", "crypto-specialist", 0.002, 3, 0.2),
        ChallengeResult("c", "pwn", False, 200, 0, "blocked", "pwn-specialist", 0.001, 1, 0.05),
    ]
    return rep


def test_aggregate_metrics():
    rep = _report()
    assert rep.total == 3 and rep.solved == 1
    assert abs(rep.solve_rate - 1 / 3) < 1e-6
    assert rep.points_captured == 50 and rep.points_available == 325
    assert rep.total_cost == 0.003
    assert rep.cost_per_solve == 0.003  # total cost / 1 solve
    assert rep.avg_seconds_per_solve == 0.1


def test_by_category():
    cats = _report().by_category()
    assert cats["crypto"]["n"] == 2 and cats["crypto"]["solved"] == 1
    assert cats["crypto"]["solve_rate"] == 0.5
    assert cats["pwn"]["solved"] == 0


def test_render_markdown_has_tables():
    md = render_markdown(_report())
    assert "1/3 solved" in md
    assert "## By category" in md and "## Challenges" in md
    assert "crypto" in md and "pwn" in md


def test_load_suite_directory():
    specs = load_suite(SUITE)
    names = {s["name"] for s in specs}
    assert {"c1-b64", "c2-xor", "m1-desc", "r1-strings", "f1-carve"} <= names
    assert len(specs) >= 7


def test_run_eval_over_offline_suite():
    specs = load_suite(SUITE)
    report = asyncio.run(run_eval(specs, concurrent=True))
    assert report.total == len(specs)
    # the five offline-solvable challenges must solve; pwn/web block
    solved = {r.name for r in report.results if r.solved}
    assert {"c1-b64", "c2-xor", "m1-desc", "r1-strings", "f1-carve"} <= solved
    assert report.solve_rate >= 5 / report.total
    # every solved flag was verified against its regex checker
    assert all(r.verified for r in report.results if r.solved)
    # pwn/web did not fabricate a flag
    for r in report.results:
        if r.name in ("p1-remote", "w1-login"):
            assert not r.solved and r.flag is None


def test_eval_report_serializes():
    report = asyncio.run(run_eval(load_suite(SUITE), concurrent=True))
    d = report.to_dict()
    assert set(d) == {"summary", "by_category", "challenges"}
    assert d["summary"]["total"] == report.total
    assert len(d["challenges"]) == report.total


def test_trace_payload_export():
    import asyncio as _a
    import json as _j
    import os as _o

    from ctfsolver.memory.store import MemoryStore
    from ctfsolver.models import Budget
    from ctfsolver.orchestrator import Orchestrator
    from ctfsolver.pipeline.intake import intake_from_spec

    with open(_o.path.join(ROOT, "examples", "repeating_xor", "challenge.json")) as f:
        spec = _j.load(f)
    spec["_base"] = _o.path.join(ROOT, "examples", "repeating_xor")
    chal = intake_from_spec(spec)
    rep = _a.run(Orchestrator(memory=MemoryStore(":memory:")).solve_challenge(chal, Budget(usd=2.0)))
    payload = rep.trace.to_payload(challenge=rep.name, summary={"status": rep.outcome.status.value})
    assert payload["challenge"] == "repeating-xor"
    assert payload["events"] and all({"t", "block", "kind"} <= set(e) for e in payload["events"])
    # the generated solver source is captured for reproducibility/console display
    assert any(e["kind"] == "script" and e["data"].get("source") for e in payload["events"])
    # JSON-serializable (the console loads it verbatim)
    assert _j.loads(_j.dumps(payload))["challenge"] == "repeating-xor"
