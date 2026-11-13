"""Sandbox contract. A specialist works entirely inside a sandbox: it reads staged
handout files, runs tools, and reaches the network only through `egress`, which is
scope-checked, budget-charged and audited on every call.

`LocalSandbox` (offline) runs a safe allow-list of read-only tools and performs no real
egress. `ContainerSandbox` (Sprint 3) runs the full toolchain in a disposable container
whose network egress is allow-listed to the target at the OS level."""
from __future__ import annotations

import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from ..guardrails.audit import AuditLog
from ..guardrails.budget import Ledger
from ..guardrails.gate import GateDecision, HumanGate
from ..guardrails.scope import ScopeError, ScopePolicy


@dataclass
class ExecResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class Sandbox(ABC):
    """Base class with the shared guardrail plumbing. Subclasses implement `_run`."""

    isolated: bool = False  # True only when code runs isolated from the host (a container)

    def __init__(
        self,
        scope: ScopePolicy,
        ledger: Ledger,
        audit: AuditLog,
        *,
        gate: Optional[HumanGate] = None,
        workdir: Optional[str] = None,
    ) -> None:
        self.scope = scope
        self.ledger = ledger
        self.audit = audit
        self.gate = gate or HumanGate()
        self._owns_workdir = workdir is None
        self.workdir = workdir or tempfile.mkdtemp(prefix="ctfsbx_")

    # --- files ------------------------------------------------------------- #
    def path(self, rel: str) -> str:
        p = os.path.realpath(os.path.join(self.workdir, rel))
        if not p.startswith(os.path.realpath(self.workdir)):
            raise ScopeError(f"path escapes sandbox: {rel}")
        return p

    # A staged handout is bounded so a special/endless source (e.g. a fifo or /dev/zero) can't
    # stream forever and fill the host disk. Raises if the source exceeds the cap.
    MAX_STAGE_BYTES = 512 * 1024 * 1024  # 512 MiB

    def stage_file(self, src: str, name: Optional[str] = None) -> str:
        name = name or os.path.basename(src)
        dst = self.path(name)
        written = 0
        with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
            while True:
                chunk = fsrc.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > self.MAX_STAGE_BYTES:
                    fdst.close()
                    os.unlink(dst)
                    raise ScopeError(f"handout {name} exceeds {self.MAX_STAGE_BYTES} bytes")
                fdst.write(chunk)
        self.audit.record("sandbox", "stage", name, bytes=written)
        return name

    def read_bytes(self, rel: str) -> bytes:
        with open(self.path(rel), "rb") as f:
            return f.read()

    def write_bytes(self, rel: str, data: bytes) -> str:
        with open(self.path(rel), "wb") as f:
            f.write(data)
        return rel

    def list_dir(self) -> list[str]:
        return sorted(os.listdir(self.workdir))

    # --- network egress (the guarded edge) --------------------------------- #
    async def egress(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        url: Optional[str] = None,
        note: str = "",
    ) -> None:
        """Gate any outbound network action. Raises ScopeError if out of scope."""
        try:
            self.scope.check(host=host, port=port, url=url)
        except ScopeError as exc:
            self.audit.record("sandbox", "egress_refused", str(exc), host=host, port=port, url=url)
            # a deliberate attempt to leave scope also pings the human gate
            self.gate.check("out_of_scope", str(exc))
            raise
        self.ledger.charge(usd=0.0, calls=1, what="egress")
        self.audit.record("sandbox", "egress", note or (url or f"{host}:{port}"),
                           host=host, port=port, url=url)

    # --- command execution ------------------------------------------------- #
    async def exec(self, argv: list[str], *, timeout: float = 30.0) -> ExecResult:
        if not argv:
            raise ValueError("empty command")
        self.ledger.charge(usd=0.0, calls=1, what=f"exec {argv[0]}")
        self.audit.record("sandbox", "exec", " ".join(argv))
        return await self._run(argv, timeout=timeout)

    @abstractmethod
    async def _run(self, argv: list[str], *, timeout: float) -> ExecResult: ...

    def close(self) -> None:
        if self._owns_workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)
