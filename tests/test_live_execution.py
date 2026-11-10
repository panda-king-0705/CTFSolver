"""Live execution: the generate->run->observe primitive, the crypto specialist solving a
repeating-key XOR by running a generated solver, and the isolation gating that keeps
provided (untrusted) code out of the non-isolated host sandbox."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopePolicy
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Category, Challenge, Target, Understanding
from ctfsolver.pipeline.intake import classify_artifact, intake_from_spec
from ctfsolver.sandbox.container import ContainerSandbox
from ctfsolver.sandbox.driver import DockerDriver, LocalProcessDriver, SandboxLimits
from ctfsolver.sandbox.local import LocalSandbox
from ctfsolver.specialists.base import SolveContext
from ctfsolver.specialists.registry import get, load_defaults
from ctfsolver.specialists.runner import run_provided, run_script
from ctfsolver.trace import Trace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ctx(chal: Challenge, sbx):
    return SolveContext(
        challenge=chal, understanding=Understanding(category=chal.category_hint),
        sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
        settings=None, ledger=sbx.ledger, techniques=[],
    )


def _local_sandbox(chal: Challenge) -> LocalSandbox:
    return LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget()), AuditLog())


# ------------------------- the live primitive ----------------------------- #
def test_run_script_executes_and_extracts_flag():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _local_sandbox(chal)
    try:
        res, flags = asyncio.run(run_script(_ctx(chal, sbx), "x.py", 'print("flag{live_run}")'))
        assert res.ok and flags == ["flag{live_run}"]
    finally:
        sbx.close()


def test_run_provided_gated_on_isolation():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _local_sandbox(chal)  # not isolated
    try:
        res, flags = asyncio.run(run_provided(_ctx(chal, sbx), "chall.py"))
        assert res is None and flags == []  # refused: host sandbox is not isolated
    finally:
        sbx.close()


# --------------------- crypto live path end to end ------------------------ #
def test_crypto_live_solves_repeating_xor():
    from ctfsolver.memory.seed import seed_techniques
    from ctfsolver.orchestrator import Orchestrator

    spec_path = os.path.join(ROOT, "examples", "repeating_xor", "challenge.json")
    with open(spec_path) as f:
        spec = json.load(f)
    spec["_base"] = os.path.dirname(spec_path)
    chal = intake_from_spec(spec)
    assert chal.category_hint is Category.CRYPTO

    mem = MemoryStore(":memory:")
    seed_techniques(mem)
    rep = asyncio.run(Orchestrator(memory=mem).solve_challenge(chal, Budget(usd=2.0)))
    assert rep.outcome.solved and rep.outcome.flag.verified
    assert rep.outcome.specialist == "crypto-specialist"
    assert any("generated repeating-key-XOR solver" in s for s in rep.outcome.steps)


# --------------------- pwn live path is container-only -------------------- #
def test_pwn_live_skipped_when_not_isolated():
    load_defaults()
    d = tempfile.mkdtemp()
    p = os.path.join(d, "vuln")
    with open(p, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 120)
    chal = Challenge(name="p", targets=[Target("tcp", "pwn.ctf", 1337)],
                     flag_format=r"flag\{[^}]+\}", category_hint=Category.PWN)
    chal.artifacts = [classify_artifact(p)]
    sbx = _local_sandbox(chal)
    sbx.stage_file(p, "vuln")
    try:
        out = asyncio.run(get(Category.PWN).solve(_ctx(chal, sbx)))
        assert out.status.value == "blocked"
        assert not any("ran generated pwntools exploit" in s for s in out.steps)
        assert any("plan:" in s for s in out.steps)  # fell back to the plan
    finally:
        sbx.close()


# --------------------------- isolation + knobs ---------------------------- #
def test_isolated_flags():
    assert DockerDriver.isolated is True
    assert LocalProcessDriver.isolated is False
    chal = Challenge(name="c")
    scope = ScopePolicy.for_challenge(chal)
    ls = LocalSandbox(scope, Ledger(Budget()), AuditLog())
    assert ls.isolated is False
    ls.close()
    cs = ContainerSandbox(scope, Ledger(Budget()), AuditLog(), driver=LocalProcessDriver())
    assert cs.isolated is False  # offline driver is not isolation
    cs.close()


def test_ptrace_capability_in_run_argv():
    argv = DockerDriver().build_run_argv(
        "/w", "none", SandboxLimits(cap_add=["SYS_PTRACE"], seccomp="unconfined"))
    s = " ".join(argv)
    assert "--cap-add SYS_PTRACE" in s
    assert "seccomp=unconfined" in s
    assert "--cap-drop ALL" in s  # still drops everything else
