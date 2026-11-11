"""Pwn specialist (scaffold).

Binary exploitation is the sharpest example of tightly-coupled work: the exploit must
be built and fired against the actual binary, iterating on real crashes. So this
specialist owns the whole challenge and, in production, drives a real toolchain
(pwntools, gdb+pwndbg, ROPgadget, one_gadget) inside the container sandbox.

Offline it does the cheap things it can -- a strings-style scan for an exposed flag and
a `checksec`/`file` recon pass -- then lays out the concrete exploit plan it would run
and BLOCKS cleanly for the container sandbox. It never guesses an exploit it cannot test.
"""
from __future__ import annotations

from typing import Optional

from ..models import Artifact, Category, Outcome, Target
from .base import SolveContext, Specialist
from .registry import register
from .remote import solve_remote
from .runner import run_script


def _elf(artifacts: list[Artifact]) -> Optional[Artifact]:
    for a in artifacts:
        if a.kind in ("binary", "elf") or a.name in ("vuln", "chall", "pwn"):
            return a
    return artifacts[0] if artifacts else None


def _tcp(targets: list[Target]) -> Optional[Target]:
    return next((t for t in targets if t.kind == "tcp"), None)


@register
class PwnSpecialist(Specialist):
    category = Category.PWN
    name = "pwn-specialist"

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format
        steps: list[str] = []
        binary = _elf(ctx.challenge.artifacts)
        remote = _tcp(ctx.challenge.targets)

        # Cheap offline win: is the flag just sitting in the binary?
        if binary is not None:
            try:
                data = ctx.sandbox.read_bytes(binary.name)
                for flag in self.find_flags(data.decode("latin-1"), fmt):
                    steps.append(f"strings {binary.name} -> flag embedded in binary")
                    return self.found(flag, f"embedded string in {binary.name}", steps)
                steps.append(f"strings {binary.name} -> no embedded flag")
            except OSError as exc:
                steps.append(f"read {binary.name} -> {exc}")

            # recon it is allowed to run (works in the container sandbox)
            res = await ctx.sandbox.exec(["checksec", "--file", binary.name])
            steps.append(f"checksec -> {'ok' if res.ok else res.stderr.strip() or 'unavailable offline'}")

        # Live instance: talk to the socket. This is the whole solve when there's no binary
        # (an interactive service), and a quick first try even when there is one -- the flag
        # may just be printed, or one prompt away. Runs in the sandbox (egress-confined).
        if remote is not None:
            flag, rsteps = await solve_remote(ctx, remote)
            steps.extend(rsteps)
            if flag:
                return self.found(flag, f"interactive solve against {remote.host}:{remote.port}",
                                  steps)

        # LIVE exploit: only in a real container (running the target binary + pwntools
        # against the remote needs isolation). Build the exploit, test locally, fire remote.
        if ctx.sandbox.isolated and binary is not None and ctx.ledger.can_afford(0.05, 3):
            exploit = await self._build_exploit(ctx, binary, remote)
            if exploit:
                res, flags = await run_script(ctx, "exploit.py", exploit, timeout=120)
                steps.append(f"ran generated pwntools exploit (rc={res.returncode})")
                if flags:
                    return self.found(flags[0], "pwntools exploit run in the container", steps)
                steps.append("exploit ran but produced no flag; falling back to the plan")

        # Not isolated (or no win yet): lay out the exploit plan from recon + techniques.
        plan = self._plan(ctx, binary, remote)
        for p in plan:
            steps.append(f"plan: {p}")

        return self.blocked(
            "exploit development requires the container sandbox (pwntools/gdb/ROPgadget "
            "with live egress to the target). Plan is ready; no exploit is fired until it "
            "can be tested locally first.",
            steps,
            hint="enable the container sandbox for this challenge",
        )

    async def _build_exploit(self, ctx: SolveContext, binary: Artifact,
                             remote: Optional[Target]) -> Optional[str]:
        """Write the pwntools exploit. Prefer a model-written one from the recon; fall
        back to a parametrized skeleton the operator/model can refine."""
        from ..llm.base import Message

        recon = "; ".join(ctx.understanding.recon[:6])
        techs = ", ".join(t.title for t in ctx.techniques) or "none recalled"
        prompt = (
            "Write a COMPLETE pwntools exploit (Python 3) for a CTF pwn challenge. It must "
            "test against the local binary, then connect to the remote and print the flag "
            "(flag{...}) to stdout. Output ONLY code.\n"
            f"Binary: ./{binary.name}\nRemote: {remote}\nRecon: {recon}\nTechniques: {techs}\n"
        )
        try:
            resp = await ctx.llm("solve_scripting").complete(
                [Message("user", prompt)], system="Expert at binary exploitation. Code only.")
            code = resp.text.strip()
            if code.startswith("```"):
                import re
                m = re.search(r"```(?:python)?\s*\n?(.*?)```", code, re.DOTALL)
                code = m.group(1).strip() if m else code
            if "pwn" in code and "sys" not in code[:20] and len(code) > 60:
                return code
        except Exception as exc:
            ctx.trace.note("solve", f"exploit model unavailable: {exc}")
        return self._exploit_skeleton(binary, remote)

    def _exploit_skeleton(self, binary: Artifact, remote: Optional[Target]) -> str:
        host = remote.host if remote else "TARGET"
        port = remote.port if remote else 0
        return (
            "from pwn import *\n"
            f"context.binary = e = ELF('./{binary.name}', checksec=False)\n"
            f"io = remote('{host}', {port}) if {bool(remote)} else process(e.path)\n"
            "# TODO: offset via cyclic, leak libc, build ROP/ret2libc, then:\n"
            "io.sendline(b'cat flag')\n"
            "print(io.recvall(timeout=5).decode('latin-1', 'ignore'))\n"
        )

    def _plan(self, ctx: SolveContext, binary, remote) -> list[str]:
        recalled = [t.title for t in ctx.techniques] or ["(no matching technique recalled)"]
        return [
            f"recon: file + checksec {binary.name if binary else '<binary>'} (NX/canary/PIE/RELRO)",
            f"recalled techniques: {', '.join(recalled)}",
            "find offset: cyclic pattern -> crash -> locate saved RIP",
            "leak: resolve libc base (puts@GOT via puts, or provided libc)",
            "build: ROP chain / ret2libc / ret2system with pwntools",
            "test LOCALLY against the binary copy; confirm shell",
            f"run REMOTE {remote} (scope-checked egress) -> cat flag",
        ]
