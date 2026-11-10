"""Eval harness -- run the solver over a challenge set and measure it.

Baseline (offline, stub provider + local sandbox) over examples/suite: 5/7 solved --
crypto/misc/rev/forensics solve offline; pwn/web correctly miss (need the container).

This is how you tune the system: point it at a directory of challenge specs (or a suite
JSON), run them under one Orchestrator, and get per-challenge and aggregate metrics --
solve rate, points captured, cost per solve, time per solve, broken down by category.
Deterministic and offline by default (the stub provider + local sandbox), so it is part
of CI and a baseline you can regress against; swap tiers/sandbox to measure a real setup.
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from ..config import Settings
from ..memory.seed import seed_techniques
from ..memory.store import MemoryStore
from ..models import Budget, Category
from ..orchestrator import Orchestrator
from ..pipeline.intake import intake_from_spec


@dataclass
class ChallengeResult:
    name: str
    category: str
    solved: bool
    points: int
    points_captured: int
    status: str
    specialist: str
    cost_usd: float
    tool_calls: int
    seconds: float
    flag: Optional[str] = None
    verified: bool = False


@dataclass
class EvalReport:
    results: list[ChallengeResult] = field(default_factory=list)
    started_at: float = 0.0
    wall_seconds: float = 0.0

    # --- aggregates --------------------------------------------------- #
    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def solved(self) -> int:
        return sum(1 for r in self.results if r.solved)

    @property
    def solve_rate(self) -> float:
        return self.solved / self.total if self.total else 0.0

    @property
    def points_captured(self) -> int:
        return sum(r.points_captured for r in self.results)

    @property
    def points_available(self) -> int:
        return sum(r.points for r in self.results)

    @property
    def total_cost(self) -> float:
        return round(sum(r.cost_usd for r in self.results), 4)

    @property
    def cost_per_solve(self) -> float:
        return round(self.total_cost / self.solved, 4) if self.solved else 0.0

    @property
    def avg_seconds_per_solve(self) -> float:
        solved = [r.seconds for r in self.results if r.solved]
        return round(sum(solved) / len(solved), 3) if solved else 0.0

    def by_category(self) -> dict[str, dict]:
        cats: dict[str, dict] = {}
        for r in self.results:
            c = cats.setdefault(r.category, {"n": 0, "solved": 0, "cost": 0.0, "points": 0, "captured": 0})
            c["n"] += 1
            c["solved"] += int(r.solved)
            c["cost"] += r.cost_usd
            c["points"] += r.points
            c["captured"] += r.points_captured
        for c in cats.values():
            c["solve_rate"] = round(c["solved"] / c["n"], 3) if c["n"] else 0.0
            c["cost"] = round(c["cost"], 4)
        return cats

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total": self.total, "solved": self.solved,
                "solve_rate": round(self.solve_rate, 3),
                "points_captured": self.points_captured,
                "points_available": self.points_available,
                "total_cost_usd": self.total_cost,
                "cost_per_solve_usd": self.cost_per_solve,
                "avg_seconds_per_solve": self.avg_seconds_per_solve,
                "wall_seconds": round(self.wall_seconds, 2),
            },
            "by_category": self.by_category(),
            "challenges": [r.__dict__ for r in self.results],
        }


def load_suite(path: str) -> list[dict]:
    """Load specs from a directory (challenge.json files) or a single suite JSON (a list
    of specs, or {"challenges": [...]})."""
    specs: list[dict] = []
    if os.path.isdir(path):
        for spec_path in sorted(glob.glob(os.path.join(path, "**", "challenge.json"), recursive=True)):
            with open(spec_path) as f:
                spec = json.load(f)
            spec["_base"] = os.path.dirname(spec_path)
            specs.append(spec)
    else:
        with open(path) as f:
            data = json.load(f)
        items = data.get("challenges", data) if isinstance(data, dict) else data
        base = os.path.dirname(os.path.abspath(path))
        for spec in items:
            spec.setdefault("_base", base)
            specs.append(spec)
    return specs


async def run_eval(
    specs: list[dict],
    *,
    settings: Optional[Settings] = None,
    budget_usd: float = 2.0,
    seed: bool = True,
    concurrent: bool = True,
) -> EvalReport:
    settings = settings or Settings()
    mem = MemoryStore(settings.db_path)
    if seed:
        seed_techniques(mem)
    orch = Orchestrator(memory=mem, settings=settings)
    report = EvalReport(started_at=time.time())

    async def _one(spec: dict) -> ChallengeResult:
        chal = intake_from_spec(spec)
        t0 = time.time()
        rep = await orch.solve_challenge(chal, Budget(usd=budget_usd))
        o = rep.outcome
        return ChallengeResult(
            name=chal.name, category=chal.category_hint.value, solved=o.solved,
            points=chal.points, points_captured=chal.points if o.solved else 0,
            status=o.status.value, specialist=o.specialist,
            cost_usd=rep.ledger_snapshot["spent_usd"],
            tool_calls=rep.ledger_snapshot["tool_calls"], seconds=round(time.time() - t0, 3),
            flag=o.flag.value if o.flag else None,
            verified=bool(o.flag and o.flag.verified),
        )

    if concurrent:
        results = await asyncio.gather(*(_one(s) for s in specs))
        report.results = list(results)
    else:
        for s in specs:
            report.results.append(await _one(s))
    report.wall_seconds = time.time() - report.started_at
    return report


def render_markdown(report: EvalReport, title: str = "CTF Solver — eval") -> str:
    s = report.to_dict()["summary"]
    lines = [f"# {title}", ""]
    lines.append(f"**{report.solved}/{report.total} solved** "
                 f"({s['solve_rate']*100:.0f}%) · "
                 f"{s['points_captured']}/{s['points_available']} pts · "
                 f"${s['total_cost_usd']} total · ${s['cost_per_solve_usd']}/solve · "
                 f"{s['avg_seconds_per_solve']}s/solve")
    lines.append("")
    lines.append("## By category")
    lines.append("| Category | Solved | Rate | Cost | Points |")
    lines.append("|---|---|---|---|---|")
    for cat, c in sorted(report.by_category().items()):
        lines.append(f"| {cat} | {c['solved']}/{c['n']} | {c['solve_rate']*100:.0f}% | "
                     f"${c['cost']} | {c['captured']}/{c['points']} |")
    lines.append("")
    lines.append("## Challenges")
    lines.append("| Challenge | Cat | Result | Specialist | Cost | Time |")
    lines.append("|---|---|---|---|---|---|")
    for r in report.results:
        mark = "✅" if r.solved else "—"
        lines.append(f"| {r.name} | {r.category} | {mark} {r.status} | {r.specialist} | "
                     f"${r.cost_usd} | {r.seconds}s |")
    lines.append("")
    return "\n".join(lines) + "\n"
