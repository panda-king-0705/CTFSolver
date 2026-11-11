"""SMB file-share instances. A real (in-process) impacket SMB server hosts a share with a
flag file; the SMB specialist path logs in anonymously, enumerates, and pulls the flag --
offline, no external network, on the LocalSandbox. Plus pure-function checks for detection
and flag extraction."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import tempfile
import threading
import time

import pytest

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopePolicy
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Category, Challenge, Target, Understanding
from ctfsolver.sandbox.local import LocalSandbox
from ctfsolver.specialists.base import SolveContext
from ctfsolver.specialists.smb import flags_from_output, looks_like_smb, solve_smb
from ctfsolver.trace import Trace


# ---------------------------- pure functions ------------------------------ #
def _chal(host="h", port=445, desc="", name="c"):
    return Challenge(name=name, targets=[Target("tcp", host, port)],
                     flag_format=r"flag\{[^}]+\}", description=desc,
                     category_hint=Category.MISC)


def _ctx(chal, sbx):
    return SolveContext(challenge=chal, understanding=Understanding(category=chal.category_hint),
                        sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
                        settings=None, ledger=sbx.ledger, techniques=[])


def test_looks_like_smb_detects_ports_and_hints():
    assert looks_like_smb(_ctx(_chal(port=445), _nosbx()), Target("tcp", "h", 445))
    assert looks_like_smb(_ctx(_chal(port=139), _nosbx()), Target("tcp", "h", 139))
    assert looks_like_smb(_ctx(_chal(port=9999, desc="SMB share, retrieve the file"), _nosbx()),
                          Target("tcp", "h", 9999))
    assert not looks_like_smb(_ctx(_chal(port=1337, desc="pwn me"), _nosbx()),
                              Target("tcp", "h", 1337))


def test_flag_extraction_prefers_challenge_then_generic():
    chal = _chal()
    ctx = _ctx(chal, _nosbx())
    out = "=== CONTENT //shares/flag.txt ===\nacademy{5mb_pr1nter_5h4re5}\n"
    assert flags_from_output(ctx, out) == ["academy{5mb_pr1nter_5h4re5}"]
    chal.flag_format = r"flag\{[^}]+\}"
    assert "flag{real}" in flags_from_output(_ctx(chal, _nosbx()), "x flag{real} academy{z}")


def _nosbx():
    chal = _chal()
    return LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget()), AuditLog())


# ---------------------------- live integration ---------------------------- #
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _smb_server(share_dir):
    from impacket.smbserver import SimpleSMBServer
    port = _free_port()
    srv = SimpleSMBServer(listenAddress="127.0.0.1", listenPort=port)
    srv.addShare("SHARES", share_dir, "public share")
    srv.setSMB2Support(True)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(0.8)
    return port, srv


def test_smb_specialist_pulls_flag_from_share():
    logging.disable(logging.CRITICAL)
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "flag.txt"), "w") as f:
        f.write("academy{smb_specialist_works}\n")
    with open(os.path.join(d, "dummy.txt"), "w") as f:
        f.write("nothing to see\n")
    try:
        port, srv = _smb_server(d)
    except Exception as exc:  # pragma: no cover - environment without a usable SMB server
        pytest.skip(f"could not start SMB server: {exc}")

    chal = _chal(host="127.0.0.1", port=port)
    sbx = LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget(usd=1.0)), AuditLog())
    try:
        flag, steps = asyncio.run(solve_smb(_ctx(chal, sbx), chal.targets[0]))
        assert flag == "academy{smb_specialist_works}", steps
        assert any("anonymous session" in s for s in steps)
        assert any("shares:" in s for s in steps)
    finally:
        sbx.close()
        try:
            srv.stop()
        except Exception:
            pass
        logging.disable(logging.NOTSET)
