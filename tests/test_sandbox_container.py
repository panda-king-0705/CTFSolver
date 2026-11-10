"""Container sandbox: egress ruleset (the network-layer scope policy), the hardened
docker run command, and the ContainerSandbox satisfying the Sandbox contract over the
offline driver -- all without a Docker daemon."""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopeError, ScopePolicy
from ctfsolver.models import Budget, Challenge, Target
from ctfsolver.sandbox.container import ContainerSandbox
from ctfsolver.sandbox.driver import DockerDriver, LocalProcessDriver, SandboxLimits
from ctfsolver.sandbox.egress import ruleset_from_scope

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _csbx(chal: Challenge) -> ContainerSandbox:
    return ContainerSandbox(
        ScopePolicy.for_challenge(chal), Ledger(Budget()),
        AuditLog(challenge_id=chal.id), driver=LocalProcessDriver(),
    )


# --------------------------- egress ruleset ------------------------------- #
def test_ruleset_allows_only_target_port():
    rs = ruleset_from_scope(ScopePolicy.for_challenge(
        Challenge(name="c", targets=[Target("tcp", "chall.ctf", 1337)])))
    assert not rs.deny_all
    assert rs.allows("chall.ctf", 1337)
    assert not rs.allows("chall.ctf", 22)            # unlisted port refused
    assert not rs.allows("evil.example.com", 443)    # out of scope refused
    assert rs.allows("127.0.0.1", 9000)              # loopback always allowed
    assert rs.allow_dns is True                       # target is a name


def test_ruleset_deny_all_without_targets():
    rs = ruleset_from_scope(ScopePolicy.for_challenge(Challenge(name="c")))
    assert rs.deny_all
    assert not rs.allows("anything.com", 80)


def test_ruleset_http_origin_ip_no_dns():
    rs = ruleset_from_scope(ScopePolicy.for_challenge(
        Challenge(name="c", targets=[Target("http", url="https://10.0.0.5:8443/app")])))
    assert rs.allows("10.0.0.5", 8443)
    assert not rs.allows("10.0.0.5", 80)
    assert rs.allow_dns is False                      # bare IP target needs no DNS


def test_iptables_default_drop_and_scope_only():
    rs = ruleset_from_scope(ScopePolicy.for_challenge(
        Challenge(name="c", targets=[Target("tcp", "target.ctf", 1337)])))
    joined = "\n".join(rs.to_iptables())
    assert "-P OUTPUT DROP" in joined                 # default deny
    assert "target.ctf --dport 1337" in joined        # the one allowed endpoint
    assert joined.strip().endswith("-A OUTPUT -j DROP")


def test_nftables_policy_drop():
    rs = ruleset_from_scope(ScopePolicy.for_challenge(
        Challenge(name="c", targets=[Target("tcp", "t.ctf", 9001)])))
    nft = rs.to_nftables()
    assert "policy drop" in nft
    assert "ip daddr t.ctf tcp dport 9001 accept" in nft


# ------------------- container sandbox over offline driver ----------------- #
def test_container_exec_allow_and_deny():
    sbx = _csbx(Challenge(name="c"))
    try:
        assert asyncio.run(sbx.exec(["echo", "hi"])).ok
        assert asyncio.run(sbx.exec(["curl", "x"])).returncode == 126
    finally:
        sbx.close()


def test_container_records_isolation_and_egress():
    chal = Challenge(name="c", targets=[Target("tcp", "chall.ctf", 1337)])
    sbx = _csbx(chal)
    try:
        starts = [r for r in sbx.audit.records if r.action == "container_start"]
        assert starts and starts[0].data["egress"] == "chall.ctf:1337"
    finally:
        sbx.close()
    assert any(r.action == "container_stop" for r in sbx.audit.records)


def test_container_egress_gate_enforced():
    sbx = _csbx(Challenge(name="c", targets=[Target("tcp", "chall.ctf", 1337)]))
    try:
        asyncio.run(sbx.egress(host="chall.ctf", port=1337))
        with pytest.raises(ScopeError):
            asyncio.run(sbx.egress(host="evil.example.com", port=80))
    finally:
        sbx.close()


def test_container_file_ops_confined():
    sbx = _csbx(Challenge(name="c"))
    try:
        sbx.write_bytes("f.txt", b"hi")
        assert sbx.read_bytes("f.txt") == b"hi"
        with pytest.raises(ScopeError):
            sbx.read_bytes("../../etc/passwd")
    finally:
        sbx.close()


# ---------------------- docker hardening (no daemon) ----------------------- #
def test_docker_run_argv_is_hardened():
    argv = DockerDriver().build_run_argv("/work/x", "none", SandboxLimits())
    s = " ".join(argv)
    for flag in ("--cap-drop ALL", "--network none", "--read-only",
                 "--pids-limit", "--security-opt no-new-privileges", "-v /work/x:/work:rw"):
        assert flag in s


def test_docker_available_returns_bool():
    assert isinstance(DockerDriver().available(), bool)  # must not raise with no daemon


# -------------------------- full e2e through container --------------------- #
def test_container_sandbox_solves_toy_e2e():
    from ctfsolver.memory.store import MemoryStore
    from ctfsolver.orchestrator import Orchestrator
    from ctfsolver.pipeline.intake import intake_from_spec

    spec_path = os.path.join(ROOT, "examples", "toy_xor", "challenge.json")
    with open(spec_path) as f:
        spec = json.load(f)
    spec["_base"] = os.path.dirname(spec_path)
    chal = intake_from_spec(spec)

    def factory(scope, ledger, audit, gate):
        return ContainerSandbox(scope, ledger, audit, gate=gate, driver=LocalProcessDriver())

    orch = Orchestrator(memory=MemoryStore(":memory:"), sandbox_factory=factory)
    rep = asyncio.run(orch.solve_challenge(chal, Budget(usd=2.0)))
    assert rep.outcome.solved and rep.outcome.flag.verified
