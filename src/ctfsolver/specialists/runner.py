"""The live-execution primitive: write a solver/exploit into the sandbox, run it, and
pull any flag out of the output. This is the generate -> run -> observe loop the whole
architecture is built around -- a single agent that can actually run code.

The script a specialist runs is code it produced (a template it filled, or an
LLM-written solver), so running it through the local sandbox is fine. Running a
*provided* (untrusted) binary or script is different: that is gated on
`ctx.sandbox.isolated`, so it only ever happens inside a real container.
"""
from __future__ import annotations

import re
import shlex
from typing import Optional

from ..sandbox.base import ExecResult
from .base import SolveContext


def extract_flags(ctx: SolveContext, *texts: str) -> list[str]:
    blob = "\n".join(t for t in texts if t)
    try:
        return list(dict.fromkeys(re.findall(ctx.challenge.flag_format, blob)))[:5]
    except re.error:
        return []


async def run_script(
    ctx: SolveContext,
    filename: str,
    source: str,
    *,
    interpreter: str = "python3",
    args: Optional[list[str]] = None,
    timeout: float = 60.0,
) -> tuple[ExecResult, list[str]]:
    """Write `source` into the sandbox as `filename` and run it. Returns (result, flags).
    The script is the specialist's own code, so this is safe on any sandbox."""
    ctx.sandbox.write_bytes(filename, source.encode())
    # record the script so the writeup is reproducible (truncated; not shown to the user)
    ctx.trace.emit("solve", "script", filename, lang=interpreter.split("/")[-1],
                   source=source[:4000])
    argv = [interpreter, filename, *(args or [])]
    res = await ctx.sandbox.exec(argv, timeout=timeout)
    flags = extract_flags(ctx, res.stdout, res.stderr)
    # carry the real stdout/stderr into the trace so the console shows actual output,
    # not just a command line -- the difference between a live run and a planted result.
    ctx.trace.cmd("solve", " ".join(argv), rc=res.returncode, flag=bool(flags),
                  stdout=(res.stdout or "")[:6000], stderr=(res.stderr or "")[:2000],
                  seconds=round(getattr(res, "duration", 0.0) or 0.0, 3))
    return res, flags


def strip_code_fence(text: str) -> str:
    """Pull code out of an LLM reply that may wrap it in ``` fences."""
    t = (text or "").strip()
    if "```" in t:
        import re
        m = re.search(r"```(?:[a-zA-Z0-9]+)?\s*\n?(.*?)```", t, re.DOTALL)
        if m:
            return m.group(1).strip()
    return t


async def llm_write_and_run(
    ctx: SolveContext,
    stage: str,
    prompt: str,
    *,
    system: str,
    filename: str = "solve.py",
    args: Optional[list[str]] = None,
    interpreter: str = "python3",
    min_len: int = 40,
    must_contain: str = "sys.argv",
    budget_usd: float = 0.004,
    timeout: float = 90.0,
) -> tuple[Optional["ExecResult"], list[str], str]:
    """Ask the model (at `stage`) to WRITE a solver, then run it in the sandbox. Returns
    (result, flags, note). Guarded by budget; tolerant of a non-code reply (never raises).
    Shared by the rev/web/forensics/crypto live paths so the generate->run loop is one thing."""
    if not ctx.ledger.can_afford(budget_usd, 2):
        return None, [], "insufficient budget for a generated solver"
    from ..llm.base import Message

    try:
        resp = await ctx.llm(stage).complete([Message("user", prompt)], system=system)
    except Exception as exc:
        return None, [], f"solver model unavailable: {exc}"
    code = strip_code_fence(resp.text)
    if len(code) < min_len or (must_contain and must_contain not in code):
        return None, [], "model reply wasn't a usable script"
    res, flags = await run_script(ctx, filename, code, args=args,
                                  interpreter=interpreter, timeout=timeout)
    return res, flags, f"ran model-written solver (rc={res.returncode})"


_INTERP = {".py": "python3", ".sh": "bash", ".js": "node", ".rb": "ruby", ".pl": "perl"}


async def run_provided(
    ctx: SolveContext,
    name: str,
    *,
    args: Optional[list[str]] = None,
    stdin: Optional[str] = None,  # reserved; wire through when a tool needs it
    timeout: float = 60.0,
) -> tuple[Optional[ExecResult], list[str]]:
    """Run a PROVIDED file (a challenge binary/script). Untrusted, so this refuses unless
    the sandbox is isolated (a real container). Returns (None, []) when skipped."""
    if not ctx.sandbox.isolated:
        ctx.trace.note("solve", f"skip running provided {name}: sandbox not isolated "
                                "(needs the container sandbox)")
        return None, []
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    interp = _INTERP.get(ext)
    if interp:
        argv = [interp, name, *(args or [])]
    else:
        q = shlex.quote(name)
        extra = " " + " ".join(shlex.quote(a) for a in args) if args else ""
        argv = ["sh", "-c", f"chmod +x ./{q} 2>/dev/null; ./{q}{extra}"]
    res = await ctx.sandbox.exec(argv, timeout=timeout)
    flags = extract_flags(ctx, res.stdout, res.stderr)
    ctx.trace.cmd("solve", " ".join(argv), rc=res.returncode, flag=bool(flags))
    return res, flags
