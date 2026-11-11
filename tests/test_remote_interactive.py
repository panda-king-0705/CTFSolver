"""Solving a live instance (nc host port) with no handouts. A mock TCP service runs on
loopback; the remote path connects, reads the banner, probes, and pulls the flag -- all
offline, no real network, on the LocalSandbox."""
from __future__ import annotations

import asyncio
import socket
import socketserver
import threading

from ctfsolver.guardrails.audit import AuditLog
from ctfsolver.guardrails.budget import Ledger
from ctfsolver.guardrails.scope import ScopePolicy
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Budget, Category, Challenge, Target, Understanding
from ctfsolver.sandbox.local import LocalSandbox
from ctfsolver.specialists.base import SolveContext
from ctfsolver.specialists.pwn import PwnSpecialist
from ctfsolver.specialists.remote import first_contact, solve_remote
from ctfsolver.trace import Trace


def _serve(handler_cls):
    """Start a threaded loopback TCP server; return (host, port, shutdown)."""
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    host, port = srv.server_address
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return host, port, srv.shutdown


class BannerFlag(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"== the vault ==\nflag{banner_on_connect}\n")


class PromptThenFlag(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"enter anything: ")
        self.request.recv(1024)  # wait for one probe line
        self.request.sendall(b"\naccess granted: flag{after_probe}\n")


def _ctx(chal: Challenge, sbx) -> SolveContext:
    return SolveContext(
        challenge=chal, understanding=Understanding(category=chal.category_hint),
        sandbox=sbx, memory=MemoryStore(":memory:"), trace=Trace(chal.id),
        settings=None, ledger=sbx.ledger, techniques=[],
    )


def _chal(host, port) -> Challenge:
    return Challenge(name="live", targets=[Target("tcp", host, port)],
                     flag_format=r"flag\{[^}]+\}", category_hint=Category.PWN)


def _sandbox(chal: Challenge) -> LocalSandbox:
    return LocalSandbox(ScopePolicy.for_challenge(chal), Ledger(Budget(usd=2.0)), AuditLog())


def test_flag_in_banner_on_connect():
    host, port, stop = _serve(BannerFlag)
    chal = _chal(host, port)
    sbx = _sandbox(chal)
    try:
        flag, steps = asyncio.run(solve_remote(_ctx(chal, sbx), chal.targets[0]))
        assert flag == "flag{banner_on_connect}"
        assert any("banner" in s for s in steps)
    finally:
        sbx.close()
        stop()


def test_flag_after_a_probe_line():
    host, port, stop = _serve(PromptThenFlag)
    chal = _chal(host, port)
    sbx = _sandbox(chal)
    try:
        # send one newline and read the response; the service then reveals the flag
        transcript, flags = asyncio.run(
            first_contact(_ctx(chal, sbx), chal.targets[0], sends=[""], read_timeout=0.5)
        )
        assert flags == ["flag{after_probe}"]
        assert "enter anything" in transcript
    finally:
        sbx.close()
        stop()


def test_pwn_specialist_solves_live_instance():
    host, port, stop = _serve(BannerFlag)
    chal = _chal(host, port)  # no binary, just the instance
    sbx = _sandbox(chal)
    try:
        out = asyncio.run(PwnSpecialist().solve(_ctx(chal, sbx)))
        assert out.solved and out.flag.value == "flag{banner_on_connect}"
        assert out.specialist == "pwn-specialist"
    finally:
        sbx.close()
        stop()


def test_server_run_solve_live_target():
    # the web API path: {name, targets:[nc ...]} -> solved via first contact
    from ctfsolver.server import ServerConfig, run_solve
    host, port, stop = _serve(BannerFlag)
    try:
        result = run_solve({"name": "instance", "targets": [f"nc {host} {port}"]},
                           ServerConfig(budget_usd=1.0))
        assert result["summary"]["flag"] == "flag{banner_on_connect}"
        assert result["summary"]["verified"] is True
    finally:
        stop()


def test_connect_error_is_handled_cleanly():
    # grab a port, close it -> connecting is refused immediately
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    chal = _chal("127.0.0.1", port)
    sbx = _sandbox(chal)
    try:
        flag, steps = asyncio.run(solve_remote(_ctx(chal, sbx), chal.targets[0]))
        assert flag is None
        assert any("CONNECT_ERROR" in s or "connect" in s for s in steps)
    finally:
        sbx.close()
