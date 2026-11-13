"""Security-hardening regression tests. The headline invariant: a REAL model's generated
code must never run on a non-isolated (host) sandbox -- that path is attacker-steerable via
challenge content. The offline stub stays allowed so the control plane remains testable."""
from __future__ import annotations

import asyncio

from ctfsolver.config import Settings, Tier
from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopePolicy
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Challenge, Understanding
from ctfsolver.sandbox.local import LocalSandbox
from ctfsolver.specialists.base import SolveContext
from ctfsolver.specialists.runner import run_script
from ctfsolver.trace import Trace


def _ctx(chal, sbx, settings):
    return SolveContext(
        challenge=chal, understanding=Understanding(category=chal.category_hint),
        sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
        settings=settings, ledger=sbx.ledger, techniques=[],
    )


def _sbx(chal):
    return LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget(usd=1.0)), AuditLog())


def _real_settings():
    s = Settings()
    s.tier_models = {t: "anthropic:claude-opus-4-8" for t in Tier}
    return s


def test_generated_code_refused_on_host_with_real_model():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _sbx(chal)  # LocalSandbox -> not isolated
    try:
        res, flags = asyncio.run(run_script(_ctx(chal, sbx, _real_settings()), "x.py",
                                            "print('flag{should_not_run}')"))
        assert res.returncode == 126, res
        assert "refused" in res.stderr.lower()
        assert flags == []  # the code never executed, so no flag was produced
    finally:
        sbx.close()


def test_generated_code_allowed_with_stub_model():
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _sbx(chal)
    try:
        res, flags = asyncio.run(run_script(_ctx(chal, sbx, Settings()), "x.py",
                                            "print('flag{stub_ok}')"))
        assert res.ok and flags == ["flag{stub_ok}"]
    finally:
        sbx.close()


def test_flag_format_sanitized_against_redos():
    from ctfsolver.models import DEFAULT_FLAG_FORMAT
    from ctfsolver.pipeline.intake import safe_flag_format
    assert safe_flag_format(r"flag\{[^}]+\}") == r"flag\{[^}]+\}"      # good pattern kept
    assert safe_flag_format(r"(a+)+$") == DEFAULT_FLAG_FORMAT           # nested quantifier -> default
    assert safe_flag_format("(" * 300) == DEFAULT_FLAG_FORMAT           # too long / uncompilable
    assert safe_flag_format("[") == DEFAULT_FLAG_FORMAT                 # does not compile


def test_stage_file_caps_size(tmp_path):
    import pytest
    from ctfsolver.guardrails.scope import ScopeError
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _sbx(chal)
    sbx.MAX_STAGE_BYTES = 16  # tighten for the test
    big = tmp_path / "big.bin"
    big.write_bytes(b"A" * 1024)
    try:
        with pytest.raises(ScopeError):
            sbx.stage_file(str(big))
    finally:
        sbx.close()


def test_local_sandbox_enforces_memory_limit(monkeypatch):
    import asyncio
    import ctfsolver.sandbox.local as local
    if local.resource is None:
        import pytest
        pytest.skip("no resource module (non-POSIX)")
    monkeypatch.setattr(local, "_MEM_BYTES", 256 * 1024 * 1024)  # 256 MiB cap for the child
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _sbx(chal)
    try:
        # allocate well past the cap -> the child must fail, not take the host down
        res = asyncio.run(sbx.exec(
            ["python3", "-c", "b=bytearray(600*1024*1024); print('ALLOCATED')"], timeout=20))
        assert "ALLOCATED" not in res.stdout and res.returncode != 0
    finally:
        sbx.close()


def test_override_env_allows_host_execution(monkeypatch):
    import ctfsolver.specialists.runner as runner
    monkeypatch.setattr(runner, "_ALLOW_UNSANDBOXED", True)
    chal = Challenge(name="c", flag_format=r"flag\{[^}]+\}")
    sbx = _sbx(chal)
    try:
        res, flags = asyncio.run(run_script(_ctx(chal, sbx, _real_settings()), "x.py",
                                            "print('flag{opted_in}')"))
        assert res.ok and flags == ["flag{opted_in}"]
    finally:
        sbx.close()
