"""Offline local sandbox: runs a safe allow-list of read-only analysis tools in a
temp working directory, and performs no real network egress. Good enough to exercise
the pipeline and for algorithmic specialists (crypto/misc) that work purely in-process.
The container sandbox in Sprint 3 subclasses the same base and does real egress."""
from __future__ import annotations

import asyncio
import time
from typing import Optional

from .base import ExecResult, Sandbox

try:  # resource limits are POSIX-only; a missing module just means no extra caps
    import resource
except ImportError:  # pragma: no cover - non-POSIX
    resource = None  # type: ignore

# Caps applied to every local child process: generated code runs here on the stub path (and on
# the opted-in host path), so bound CPU, memory, file size and process count to stop a runaway
# or fork-bomb from taking the host down. The container path has its own --memory/--pids/--cpus.
_CPU_SECONDS = 60
_MEM_BYTES = 2 * 1024 * 1024 * 1024      # 2 GiB address space
_FSIZE_BYTES = 256 * 1024 * 1024         # 256 MiB max single file written
_NPROC = 256                             # fork-bomb guard


def _limit_child() -> None:  # pragma: no cover - runs in the forked child
    if resource is None:
        return
    for res, soft in ((resource.RLIMIT_CPU, _CPU_SECONDS),
                      (resource.RLIMIT_AS, _MEM_BYTES),
                      (resource.RLIMIT_FSIZE, _FSIZE_BYTES),
                      (getattr(resource, "RLIMIT_NPROC", None), _NPROC)):
        if res is None:
            continue
        try:
            resource.setrlimit(res, (soft, soft))
        except (ValueError, OSError):
            pass

# Read-only tools a local, non-container sandbox may run. Anything that mutates the
# host, escalates, or reaches the network is intentionally absent.
SAFE_BINS = frozenset(
    {"file", "strings", "cat", "head", "tail", "ls", "wc", "xxd", "od", "nm",
     "objdump", "readelf", "checksec", "true", "echo", "python3", "base64", "sha256sum"}
)


class LocalSandbox(Sandbox):
    def __init__(self, *args, allow_bins: Optional[frozenset[str]] = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.allow_bins = allow_bins or SAFE_BINS

    async def _run(self, argv: list[str], *, timeout: float) -> ExecResult:
        bin_name = argv[0].split("/")[-1]
        if bin_name not in self.allow_bins:
            self.audit.record("sandbox", "exec_refused", argv[0],
                              reason="not in local allow-list")
            return ExecResult(argv, returncode=126,
                              stderr=f"{bin_name}: not permitted in local sandbox "
                                     f"(needs the container sandbox)")
        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, cwd=self.workdir,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                preexec_fn=_limit_child if resource is not None else None,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ExecResult(argv, returncode=124, duration=time.time() - t0, timed_out=True)
            return ExecResult(
                argv, returncode=proc.returncode or 0,
                stdout=out.decode("utf-8", "replace"),
                stderr=err.decode("utf-8", "replace"),
                duration=time.time() - t0,
            )
        except FileNotFoundError:
            return ExecResult(argv, returncode=127, stderr=f"{argv[0]}: not found",
                              duration=time.time() - t0)
