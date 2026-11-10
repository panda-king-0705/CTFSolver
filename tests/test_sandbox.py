"""Sandbox: command allow-list, scope-checked egress, confined file access."""
from __future__ import annotations

import asyncio
import os

import pytest

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopeError, ScopePolicy
from ctfsolver.models import Budget, Challenge, Target
from ctfsolver.sandbox.local import LocalSandbox


def _sandbox(challenge: Challenge) -> LocalSandbox:
    scope = ScopePolicy.for_challenge(challenge)
    ledger = Ledger(Budget())
    audit = AuditLog(challenge_id=challenge.id)
    return LocalSandbox(scope, ledger, audit)


def test_exec_allow_list():
    sbx = _sandbox(Challenge(name="c"))
    try:
        res = asyncio.run(sbx.exec(["echo", "hello"]))
        assert res.ok and "hello" in res.stdout
        refused = asyncio.run(sbx.exec(["curl", "http://x"]))
        assert refused.returncode == 126  # not in local allow-list
    finally:
        sbx.close()


def test_file_access_confined():
    sbx = _sandbox(Challenge(name="c"))
    try:
        sbx.write_bytes("note.txt", b"data")
        assert sbx.read_bytes("note.txt") == b"data"
        with pytest.raises(ScopeError):
            sbx.read_bytes("../../etc/passwd")
    finally:
        sbx.close()


def test_egress_scope_enforced():
    chal = Challenge(name="c", targets=[Target("tcp", "chall.ctf", 1337)])
    sbx = _sandbox(chal)
    try:
        asyncio.run(sbx.egress(host="chall.ctf", port=1337, note="connect"))
        assert sbx.ledger.tool_calls >= 1  # egress charged
        with pytest.raises(ScopeError):
            asyncio.run(sbx.egress(host="attacker.example.com", port=80))
        # the refusal was audited
        assert any(r.action == "egress_refused" for r in sbx.audit.records)
    finally:
        sbx.close()


def test_stage_file(tmp_path):
    src = tmp_path / "handout.bin"
    src.write_bytes(b"\x7fELF payload")
    sbx = _sandbox(Challenge(name="c"))
    try:
        name = sbx.stage_file(str(src))
        assert name == "handout.bin"
        assert sbx.read_bytes("handout.bin").startswith(b"\x7fELF")
    finally:
        sbx.close()
