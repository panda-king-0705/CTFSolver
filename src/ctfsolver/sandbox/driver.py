"""Container drivers. A driver provides the actual execution substrate for a
`ContainerSandbox`:

- `DockerDriver` runs a disposable, hardened, network-confined container (the real thing,
  where a Docker daemon and a toolbox image exist).
- `LocalProcessDriver` runs commands in the sandbox workdir on the host with a safe
  read-only tool allow-list and no real egress. It is the offline/CI substrate and keeps
  the ContainerSandbox contract fully testable without a daemon.

The sandbox charges the ledger and audits before calling the driver, and the in-process
`egress()` gate enforces scope regardless of driver. A driver's extra job is OS-level
isolation: the Docker driver applies the egress ruleset to the container's network so a
tool that opens its own socket still cannot leave scope.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from .base import ExecResult
from .egress import EgressRuleset
from .local import SAFE_BINS


@dataclass
class SandboxLimits:
    """Hard resource caps for a container. Defence in depth with the budget ledger.

    `cap_add` / `seccomp` loosen only what a tool needs (e.g. SYS_PTRACE for gdb) and
    never touch the network confinement. `extra_run_args` are appended verbatim."""

    image: str = os.getenv("CTFSOLVER_TOOLBOX_IMAGE", "ctfsolver/toolbox:latest")
    memory: str = "512m"
    cpus: float = 1.0
    pids: int = 256
    tmpfs_size: str = "64m"
    default_timeout: float = 60.0
    cap_add: list[str] = field(default_factory=list)
    seccomp: Optional[str] = None  # e.g. "unconfined" for some gdb/ptrace setups
    extra_run_args: list[str] = field(default_factory=list)


async def _spawn(argv: list[str], *, cwd: Optional[str] = None, timeout: float = 30.0) -> ExecResult:
    """Run a command, capped by timeout. Shared by both drivers."""
    t0 = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=cwd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return ExecResult(argv, returncode=127, stderr=f"{argv[0]}: not found",
                          duration=time.time() - t0)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ExecResult(argv, returncode=124, duration=time.time() - t0, timed_out=True)
    return ExecResult(
        argv, returncode=proc.returncode or 0,
        stdout=out.decode("utf-8", "replace"), stderr=err.decode("utf-8", "replace"),
        duration=time.time() - t0,
    )


class ContainerDriver(ABC):
    name: str = "driver"
    isolated: bool = False  # True only when the substrate isolates code from the host

    def available(self) -> bool:
        return True

    @abstractmethod
    def start(self, *, workdir: str, ruleset: EgressRuleset, limits: SandboxLimits) -> None: ...

    @abstractmethod
    async def exec(self, argv: list[str], *, timeout: float, workdir: str) -> ExecResult: ...

    @abstractmethod
    def stop(self) -> None: ...


# --------------------------------------------------------------------------- #
# Offline / CI substrate
# --------------------------------------------------------------------------- #
class LocalProcessDriver(ContainerDriver):
    """Runs on the host, so it is NOT isolated -- it therefore restricts commands to a
    safe read-only allow-list and performs no real network egress. Files live in the
    shared sandbox workdir, so the sandbox's own file ops just work."""

    name = "local-process"
    isolated = False  # runs on the host -- never run untrusted provided code through this

    def __init__(self, allow_bins: Optional[frozenset[str]] = None) -> None:
        self.allow_bins = allow_bins or SAFE_BINS
        self._ruleset: Optional[EgressRuleset] = None

    def start(self, *, workdir: str, ruleset: EgressRuleset, limits: SandboxLimits) -> None:
        self._ruleset = ruleset  # recorded for parity; no real network is opened

    async def exec(self, argv: list[str], *, timeout: float, workdir: str) -> ExecResult:
        binname = argv[0].split("/")[-1]
        if binname not in self.allow_bins:
            return ExecResult(argv, returncode=126,
                              stderr=f"{binname}: not permitted by local driver "
                                     f"(needs the container/Docker driver)")
        return await _spawn(argv, cwd=workdir, timeout=timeout)

    def stop(self) -> None:
        self._ruleset = None


# --------------------------------------------------------------------------- #
# Real container substrate
# --------------------------------------------------------------------------- #
class DockerDriver(ContainerDriver):
    """A disposable, hardened container. Egress is confined to the target: with no
    targets the container runs `--network none`; with targets it runs on an isolated
    bridge and the egress ruleset is applied at the host firewall. The container drops
    all capabilities, runs read-only with a small tmpfs, and is force-removed on stop."""

    name = "docker"
    isolated = True  # a real container: safe to run the target binary / provided code

    def __init__(self, docker_bin: str = "docker") -> None:
        self.docker = docker_bin
        self.cid = f"ctfsbx_{uuid.uuid4().hex[:12]}"
        self.network: Optional[str] = None
        self._started = False

    def available(self) -> bool:
        import subprocess

        try:
            r = subprocess.run([self.docker, "info"], capture_output=True, timeout=10)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def build_run_argv(self, workdir: str, net: str, limits: SandboxLimits) -> list[str]:
        """The `docker run` command. Exposed for testing the hardening flags without a
        daemon."""
        argv = [
            self.docker, "run", "-d", "--rm", "--name", self.cid,
            "--network", net,
            "-v", f"{workdir}:/work:rw", "-w", "/work",
            "--memory", limits.memory, "--cpus", str(limits.cpus),
            "--pids-limit", str(limits.pids),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", f"/tmp:rw,size={limits.tmpfs_size}",
        ]
        for cap in limits.cap_add:
            argv += ["--cap-add", cap]  # e.g. SYS_PTRACE for gdb -- network stays confined
        if limits.seccomp:
            argv += ["--security-opt", f"seccomp={limits.seccomp}"]
        argv += limits.extra_run_args
        argv += [limits.image, "sleep", "infinity"]
        return argv

    def start(self, *, workdir: str, ruleset: EgressRuleset, limits: SandboxLimits) -> None:
        import subprocess

        net = "none"
        if not ruleset.deny_all:
            net = f"{self.cid}_net"
            subprocess.run([self.docker, "network", "create", "--internal", net],
                           capture_output=True, timeout=30)
            self.network = net
        argv = self.build_run_argv(workdir, net, limits)
        res = subprocess.run(argv, capture_output=True, timeout=60)
        if res.returncode != 0:
            raise RuntimeError(f"docker run failed: {res.stderr.decode('utf-8', 'replace')[:200]}")
        self._started = True
        if not ruleset.deny_all:
            self._apply_host_firewall(ruleset)

    def _apply_host_firewall(self, ruleset: EgressRuleset) -> None:
        """Pin the container's egress to the allow-list at the host firewall. Requires
        privilege; best-effort and never fatal (the --internal network is the floor of
        protection even if this step is unavailable)."""
        import subprocess

        try:
            for rule_args in ruleset.to_iptables(chain="DOCKER-USER"):
                subprocess.run(["iptables", *rule_args.split()], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass  # the internal network still blocks external egress

    async def exec(self, argv: list[str], *, timeout: float, workdir: str) -> ExecResult:
        return await _spawn([self.docker, "exec", "-w", "/work", self.cid, *argv],
                            timeout=timeout)

    def stop(self) -> None:
        import subprocess

        if self._started:
            subprocess.run([self.docker, "rm", "-f", self.cid], capture_output=True, timeout=30)
            self._started = False
        if self.network:
            subprocess.run([self.docker, "network", "rm", self.network],
                           capture_output=True, timeout=30)
            self.network = None
