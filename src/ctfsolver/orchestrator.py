"""The orchestrator -- the executive layer.

It runs the pipeline for one challenge (triage -> route -> solve -> verify -> learn)
under full guardrails, with a bounded escalation ladder; and it runs many challenges at
once, prioritized by points-per-effort. It decides, budgets, routes, verifies and
remembers. It never fragments a challenge -- a specialist owns each one whole, and a
cross-category challenge is re-routed whole via WAITING/reroute_to.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .config import Settings
from .guardrails.audit import AuditLog
from .guardrails.budget import BudgetExceeded, Ledger
from .guardrails.gate import Approver, HumanGate
from .guardrails.scope import ScopePolicy
from .llm.base import LLMClient, Message, get_client
from .llm.stub import StubClient
from .memory.store import MemoryStore
from .models import Budget, Category, Challenge, Flag, Outcome, OutcomeStatus, Attempt, Technique
from .pipeline.route import route
from .pipeline.triage import triage
from .pipeline.verify import verify
from .pipeline.writeup import generate_writeup
from .sandbox.base import Sandbox
from .sandbox.local import LocalSandbox
from .specialists.base import SolveContext, Specialist
from .specialists.metacognition import metacognitive_solve
from .specialists.registry import get as get_specialist
from .specialists.registry import load_defaults
from .trace import Trace

# Rough per-category effort estimate (USD) for the points-per-effort scheduler.
_EST_COST = {
    Category.PWN: 0.40, Category.WEB: 0.30, Category.REV: 0.35,
    Category.FORENSICS: 0.25, Category.CRYPTO: 0.15, Category.MISC: 0.10,
    Category.UNKNOWN: 0.20,
}


class _BudgetedClient:
    """Wraps any LLMClient so every call is metered against the ledger and shows up in the
    trace as an `llm` event -- stage, model, latency, tokens, cost, and a reply preview.
    That event is how the console shows the agent actually thinking; `stub=True` marks the
    offline placeholder model honestly, so a stubbed run never masquerades as real reasoning."""

    def __init__(self, inner: LLMClient, ledger: Ledger,
                 trace: Optional[Trace] = None, stage: str = "") -> None:
        self._inner = inner
        self._ledger = ledger
        self._trace = trace
        self._stage = stage
        self.model = inner.model

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2):
        if not self._ledger.can_afford(0.01, 1):
            raise BudgetExceeded("no budget left for an LLM call")
        import time as _time
        t0 = _time.time()
        resp = await self._inner.complete(
            messages, system=system, max_tokens=max_tokens, temperature=temperature
        )
        latency_ms = round((_time.time() - t0) * 1000)
        self._ledger.charge(usd=resp.cost_usd, calls=1, what="llm")
        if self._trace is not None:
            block = (self._stage or "solve").split("_", 1)[0]
            self._trace.emit(
                block, "llm", f"{self.model} · {latency_ms}ms",
                stage=self._stage, model=str(self.model),
                stub=str(self.model).startswith("stub:"),
                latency_ms=latency_ms, tokens_in=resp.input_tokens,
                tokens_out=resp.output_tokens, cost=round(resp.cost_usd, 6),
                preview=(resp.text or "").strip().replace("\n", " ")[:200],
            )
        return resp


SandboxFactory = Callable[[ScopePolicy, Ledger, AuditLog, HumanGate], Sandbox]


def _default_sandbox(scope, ledger, audit, gate) -> Sandbox:
    return LocalSandbox(scope, ledger, audit, gate=gate)


@dataclass
class SolveReport:
    challenge_id: str
    name: str
    outcome: Outcome
    trace: Trace
    audit: AuditLog
    ledger_snapshot: dict
    writeup: str = ""  # shareable markdown report of the solve (Learn stage)


class Orchestrator:
    def __init__(
        self,
        memory: Optional[MemoryStore] = None,
        settings: Optional[Settings] = None,
        *,
        approver: Optional[Approver] = None,
        sandbox_factory: Optional[SandboxFactory] = None,
    ) -> None:
        load_defaults()
        self.settings = settings or Settings()
        self.memory = memory or MemoryStore(self.settings.db_path)
        self.gate = HumanGate(approver=approver, enabled=self.settings.allow_human_gate) \
            if approver else HumanGate(enabled=self.settings.allow_human_gate)
        self.sandbox_factory = sandbox_factory or _default_sandbox
        self._client_cache: dict[str, LLMClient] = {}

    # ------------------------------------------------------------------ #
    def _client(self, model: str) -> LLMClient:
        if model not in self._client_cache:
            try:
                self._client_cache[model] = get_client(model)
            except Exception:
                self._client_cache[model] = StubClient(model.split(":")[-1])
        return self._client_cache[model]

    def _llm_factory(self, ledger: Ledger,
                     trace: Optional[Trace] = None) -> Callable[[str], LLMClient]:
        def factory(stage: str) -> LLMClient:
            return _BudgetedClient(self._client(self.settings.model_for(stage)), ledger,
                                   trace=trace, stage=stage)
        return factory

    # ------------------------------------------------------------------ #
    async def solve_challenge(
        self,
        challenge: Challenge,
        budget: Optional[Budget] = None,
        trace: Optional[Trace] = None,
    ) -> SolveReport:
        ledger = Ledger(budget or Budget())
        trace = trace or Trace(challenge.id)
        trace.challenge_id = challenge.id
        audit = AuditLog(trace, challenge.id)
        scope = ScopePolicy.for_challenge(challenge)
        llm_factory = self._llm_factory(ledger, trace)

        with trace.span("orchestrate", challenge.name):
            audit.record("orchestrator", "scope", "authorized",
                         scope=sorted(scope.allowed_hostports | scope.allowed_origins
                                      | scope.allowed_handles) or sorted(scope.allowed_hosts))
            # --- triage ---
            understanding = await triage(
                challenge, self.memory, trace, llm_factory, self.settings,
                can_afford_llm=ledger.can_afford(0.01, 1),
            )
            # --- route (whole hand-off) ---
            with trace.span("route"):
                decision = route(challenge, understanding)
                trace.note("route", decision.rationale)
            specialist = decision.specialist
            if specialist is None:
                outcome = Outcome(OutcomeStatus.FAILED, notes="no specialist available")
                return await self._finish(challenge, understanding, outcome, trace, audit, ledger)

            # --- solve with a bounded escalation ladder ---
            outcome = await self._solve_with_escalation(
                challenge, understanding, specialist, scope, ledger, audit, trace, llm_factory
            )
            return await self._finish(challenge, understanding, outcome, trace, audit, ledger)

    # ------------------------------------------------------------------ #
    async def _solve_with_escalation(
        self, challenge, understanding, specialist: Specialist, scope, ledger, audit, trace, llm_factory
    ) -> Outcome:
        tried: set[str] = set()
        current = specialist
        last: Optional[Outcome] = None

        for step in range(self.settings.max_escalations + 1):
            if current is None or current.name in tried:
                break
            tried.add(current.name)

            techniques = self.memory.recall_techniques(
                " ".join([understanding.category.value, understanding.subtype]
                         + understanding.recon[:3]),
                category=understanding.category, limit=5,
            )
            sandbox = self.sandbox_factory(scope, ledger, audit, self.gate)
            self._stage(challenge, sandbox, trace)
            ctx = SolveContext(
                challenge=challenge, understanding=understanding, sandbox=sandbox,
                memory=self.memory, trace=trace, settings=self.settings, ledger=ledger,
                techniques=techniques, _llm_factory=llm_factory,
            )
            try:
                with trace.span(f"solve:{current.name}", f"escalation={step}"):
                    outcome = await current.solve(ctx)
                    # Don't give up when the specialist has no canned path: reason through it.
                    # Metacognition tries candidate approaches cheap-first (standard tier, few
                    # steps), reflects, and escalates to the frontier model only when it's worth
                    # it — early-stopping on a real external blocker. No-ops on the offline stub.
                    if not outcome.solved:
                        flag, asteps = await metacognitive_solve(ctx, points=challenge.points)
                        outcome.steps = list(outcome.steps) + asteps
                        if flag:
                            outcome = Outcome(
                                status=OutcomeStatus.SOLVED,
                                flag=Flag(value=flag, source="agentic reasoning loop"),
                                steps=outcome.steps, specialist=f"{current.name}+agent",
                            )
            except BudgetExceeded as exc:
                trace.note("solve", f"budget stop: {exc}")
                outcome = Outcome(OutcomeStatus.FAILED, notes=f"budget: {exc}", specialist=current.name)
            finally:
                sandbox.close()  # disposable: a fresh sandbox per attempt

            last = outcome

            # --- solved? verify (the flag is the oracle) ---
            if outcome.solved:
                accepted, rec = await verify(outcome.flag, challenge, trace)
                if accepted:
                    audit.record(current.name, "flag", outcome.flag.value, verified=True)
                    return outcome
                trace.note("solve", f"flag rejected on verify ({rec.get('reason')}); escalating")
                outcome.status = OutcomeStatus.FAILED  # a non-verifying flag is not a solve

            # --- whole hand-off to another category ---
            if outcome.status is OutcomeStatus.WAITING and outcome.reroute_to:
                nxt = get_specialist(outcome.reroute_to)
                trace.note("route", f"whole hand-off -> {outcome.reroute_to.value}")
                understanding.category = outcome.reroute_to
                current = nxt
                continue

            # --- blocked/failed: climb the ladder ---
            if step < self.settings.max_escalations:
                if outcome.hint_request:
                    trace.note("escalate", f"hint requested: {outcome.hint_request}")
                # second opinion from the generalist, then surface to the human gate
                generalist = get_specialist(Category.MISC)
                if generalist and generalist.name not in tried:
                    trace.note("escalate", "second opinion -> misc-specialist")
                    current = generalist
                    continue
                decision = self.gate.check("legal_sensitive",
                                           f"stuck on {challenge.name}; surface to operator")
                trace.note("escalate", f"human gate: {decision.value}")
            break

        return last or Outcome(OutcomeStatus.FAILED, notes="no attempt made")

    # ------------------------------------------------------------------ #
    def _stage(self, challenge: Challenge, sandbox: Sandbox, trace: Trace) -> None:
        import os
        for art in challenge.artifacts:
            if os.path.exists(art.path):
                try:
                    sandbox.stage_file(art.path, art.name)
                except OSError as exc:
                    trace.note("intake", f"stage {art.name} failed: {exc}")

    # ------------------------------------------------------------------ #
    async def _finish(self, challenge, understanding, outcome, trace, audit, ledger) -> SolveReport:
        """Report + online learning: record the episode, on a win bank the technique and
        bump the recalled ones, and generate the shareable writeup."""
        snap = ledger.snapshot()
        outcome.cost_usd = snap["spent_usd"]
        outcome.tool_calls = snap["tool_calls"]
        writeup = ""
        with trace.span("learn"):
            attempt = Attempt(
                challenge_id=challenge.id, specialist=outcome.specialist or "orchestrator",
                outcome=outcome, ended_at=time.time(),
            )
            self.memory.add_episode(attempt)
            if outcome.solved:
                tech = Technique(
                    title=f"{understanding.category.value}: solved {challenge.name}",
                    category=understanding.category,
                    pattern="; ".join(understanding.recon[:4]) or understanding.subtype,
                    recipe="; ".join(outcome.steps[-6:]),
                    tags=[understanding.category.value] + ([understanding.subtype] if understanding.subtype else []),
                    source=challenge.name, uses=1, wins=1,
                )
                self.memory.add_technique(tech)
                for tid in outcome.used_technique_ids:
                    self.memory.bump_technique(tid, win=True)
                if challenge.flag_format:
                    self.memory.add_concept(f"flag_format:{challenge.name}", challenge.flag_format,
                                            tags=[understanding.category.value])
                trace.note("learn", f"banked technique; verified flag {outcome.flag.value}")
            else:
                for tid in outcome.used_technique_ids:
                    self.memory.bump_technique(tid, win=False)
                trace.note("learn", f"episode logged ({outcome.status.value})")

            # writeup (templated by default; LLM-polished summary when enabled)
            llm = self._llm_factory(ledger)("learn") if self.settings.writeup_llm else None
            writeup = await generate_writeup(challenge, understanding, outcome, snap,
                                             trace=trace, llm=llm)
            trace.note("learn", "writeup generated")

        return SolveReport(
            challenge_id=challenge.id, name=challenge.name, outcome=outcome,
            trace=trace, audit=audit, ledger_snapshot=snap, writeup=writeup,
        )

    # ------------------------------------------------------------------ #
    async def run(
        self, work: list[tuple[Challenge, Optional[Budget]]]
    ) -> dict[str, SolveReport]:
        """Run many challenges concurrently, prioritized by points-per-effort."""
        def priority(item: tuple[Challenge, Optional[Budget]]) -> float:
            chal = item[0]
            est = _EST_COST.get(chal.category_hint, 0.2)
            return chal.points / max(est, 0.01)

        ordered = sorted(work, key=priority, reverse=True)
        sem = asyncio.Semaphore(self.settings.max_concurrent)
        results: dict[str, SolveReport] = {}

        async def _one(chal: Challenge, budget: Optional[Budget]) -> None:
            async with sem:
                results[chal.id] = await self.solve_challenge(chal, budget)

        await asyncio.gather(*(_one(c, b) for c, b in ordered))
        return results
