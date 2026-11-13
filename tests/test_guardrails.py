"""Guardrails: scope confinement (the one that matters), budget ledger, gate, audit."""
from __future__ import annotations

import pytest

from ctfsolver.guardrails.budget import BudgetExceeded, Ledger
from ctfsolver.guardrails.gate import GateDecision, HumanGate
from ctfsolver.guardrails.scope import ScopeError, ScopePolicy
from ctfsolver.models import Budget, Challenge, Target


def test_scope_allows_only_designated_target():
    chal = Challenge(name="c", targets=[Target("tcp", "chall.ctf", 1337)])
    p = ScopePolicy.for_challenge(chal)
    # in scope
    p.check(host="chall.ctf", port=1337)
    # out of scope -> refused
    with pytest.raises(ScopeError):
        p.check(host="evil.example.com", port=443)
    with pytest.raises(ScopeError):
        p.check(host="chall.ctf", port=22)  # right host, wrong (unlisted) port? host-allowed


def test_scope_http_origin():
    chal = Challenge(name="c", targets=[Target("http", url="https://web.ctf:8443/app")])
    p = ScopePolicy.for_challenge(chal)
    p.check(url="https://web.ctf:8443/admin")  # same origin, different path -> ok
    with pytest.raises(ScopeError):
        p.check(url="https://other.ctf/")


def test_scope_local_instance_handle():
    # a bare handle authorizes the handle itself but NOT all of loopback (SSRF defence)
    chal = Challenge(name="c", local_instance="ctr://abc123")
    p = ScopePolicy.for_challenge(chal)
    p.check(handle="ctr://abc123")
    with pytest.raises(ScopeError):
        p.check(host="127.0.0.1", port=5000)  # loopback is NOT wide open
    with pytest.raises(ScopeError):
        p.check(handle="ctr://someone-else")


def test_scope_local_instance_pins_to_port():
    # when the instance names a loopback port, only that port is authorized
    chal = Challenge(name="c", local_instance="127.0.0.1:5000")
    p = ScopePolicy.for_challenge(chal)
    p.check(host="127.0.0.1", port=5000)
    with pytest.raises(ScopeError):
        p.check(host="127.0.0.1", port=6000)  # a different local service stays off-limits


def test_budget_ledger_charges_and_stops():
    led = Ledger(Budget(usd=0.01, tool_calls=3, wall_seconds=100))
    led.charge(usd=0.004, calls=1, what="llm")
    assert led.can_afford(0.004, 1)
    with pytest.raises(BudgetExceeded):
        led.charge(usd=0.01, calls=1)  # would exceed usd cap
    # call cap
    led2 = Ledger(Budget(usd=10, tool_calls=2, wall_seconds=100))
    led2.charge(calls=1)
    led2.charge(calls=1)
    with pytest.raises(BudgetExceeded):
        led2.charge(calls=1)


def test_human_gate_denies_by_default():
    g = HumanGate()  # default approver denies
    assert g.check("exfiltrate", "x") is GateDecision.DENIED
    assert g.check("read_file", "x") is GateDecision.ALLOWED  # not sensitive

    g2 = HumanGate(approver=lambda kind, detail: True)
    assert g2.check("destructive", "x") is GateDecision.APPROVED
