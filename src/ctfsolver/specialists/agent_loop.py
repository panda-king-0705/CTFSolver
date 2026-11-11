"""The fallback that stops the solver from giving up.

When the category specialists don't crack a challenge, don't return BLOCKED -- reason through
it the way a human CTF player does. The model drives a bounded think -> act -> observe loop
with a real sandbox: it proposes ONE action (a shell command or a Python script), the sandbox
runs it, the output comes back, and the model adapts. It keeps going until a flag appears or
the budget/iteration cap is hit.

Everything runs in the sandbox, so it is scope-checked, egress-confined (under --container),
budget-charged and audited. A candidate only counts when it matches the flag format -- the
loop never fabricates a flag.

It needs a real model (subscription or API). On the offline stub it no-ops cleanly, so the
control plane stays deterministic and offline-testable.
"""
from __future__ import annotations

import re
from typing import Optional

from ..llm.base import Message, extract_json
from .base import SolveContext
from .runner import extract_flags, run_script

_GENERIC_FLAG = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{1,256}\}")

_SYSTEM = (
    "You are an elite CTF player working in a disposable Linux sandbox with the standard "
    "toolchain (python3, nc, curl, socat, openssl, strings, xxd, file, binwalk, foremost, "
    "exiftool, steghide, zsteg, gdb, radare2, pwntools, ROPgadget, pycryptodome, sympy, z3, "
    "impacket, scapy). The challenge's files are in the current working directory.\n\n"
    "Solve it by taking ONE action at a time and reading the result before the next. Respond "
    "with STRICT JSON only -- no prose, no markdown:\n"
    '{"thought":"<one short line>","tool":"shell"|"python"|"submit",'
    '"input":"<shell command or python3 source>","flag":"<only when tool=submit>"}\n\n'
    "Use `shell` for tools and one-liners, `python` for scripts (it is run with python3). "
    "Print what you learn so you can see it. When you have recovered the flag, use "
    "tool=\"submit\" with the exact flag string. Be resourceful and keep going."
)


def _flags(ctx: SolveContext, text: str) -> list[str]:
    found = extract_flags(ctx, text)
    if not found:
        found = list(dict.fromkeys(_GENERIC_FLAG.findall(text or "")))
    return found


def _head(ctx: SolveContext, name: str, n: int = 240) -> str:
    try:
        data = ctx.sandbox.read_bytes(name)
    except Exception:
        return "(unreadable)"
    return data[:n].decode("latin-1", "replace")


def _context(ctx: SolveContext) -> str:
    c = ctx.challenge
    lines = [f"Challenge: {c.name}"]
    if c.category_hint:
        lines.append(f"Category (guess): {c.category_hint.value}")
    if c.description:
        lines.append(f"Description: {c.description}")
    if c.targets:
        lines.append("Targets: " + ", ".join(t.raw for t in c.targets))
    lines.append(f"Flag format (regex): {c.flag_format}")
    if ctx.techniques:
        lines.append("Recalled techniques: " + "; ".join(t.title for t in ctx.techniques[:5]))
    if c.artifacts:
        lines.append("Files in the working directory:")
        for a in c.artifacts:
            lines.append(f"  - {a.name} ({a.kind}, {a.size}B) head={_head(ctx, a.name)!r}")
    return "\n".join(lines)


async def _run_action(ctx: SolveContext, i: int, tool: str, inp: str):
    """Execute one action in the sandbox. Returns (output_text, flags)."""
    if tool == "python":
        res, _ = await run_script(ctx, f"agent_step{i}.py", inp, timeout=90)
        out = (res.stdout or "") + (("\n[stderr] " + res.stderr) if res.stderr else "")
        return out, _flags(ctx, out)
    # shell
    res = await ctx.sandbox.exec(["sh", "-c", inp], timeout=90)
    out = (res.stdout or "") + (("\n[stderr] " + res.stderr) if res.stderr else "")
    ctx.trace.cmd("solve", inp, rc=res.returncode, stdout=out[:6000],
                  seconds=round(getattr(res, "duration", 0.0) or 0.0, 3))
    return out, _flags(ctx, out)


async def agentic_solve(ctx: SolveContext, *, max_iters: int = 6) -> tuple[Optional[str], list[str]]:
    """Reason through the challenge with the model + sandbox. Returns (flag | None, steps)."""
    steps: list[str] = []
    client = ctx.llm("solve_strategy")
    if str(getattr(client, "model", "")).startswith("stub:"):
        steps.append("agentic loop skipped: needs a real model "
                     "(run with --subscription or an API key)")
        return None, steps

    ctx.trace.note("solve", "no specialist flag yet — entering the agentic reasoning loop")
    context = _context(ctx)
    history: list[str] = []
    seen: dict[str, int] = {}  # loop detection: repeated actions get a nudge, not a re-run

    for i in range(max_iters):
        if not ctx.ledger.can_afford(0.02, 1):
            steps.append(f"agentic loop stopped at iter {i}: out of budget")
            break
        prompt = (context + "\n\nHistory so far:\n"
                  + ("\n".join(history) if history else "(nothing yet)")
                  + "\n\nYour next action (JSON only):")
        try:
            resp = await client.complete([Message("user", prompt)], system=_SYSTEM, max_tokens=900)
        except Exception as exc:
            steps.append(f"agentic loop: model error at iter {i}: {exc}")
            break

        try:
            action = extract_json(resp.text)
            if not isinstance(action, dict):
                raise ValueError("not an object")
        except Exception:
            history.append("SYSTEM: last reply was not valid JSON. Reply with JSON only.")
            continue

        thought = str(action.get("thought", ""))[:140]
        tool = str(action.get("tool", "")).lower()
        if thought:
            ctx.trace.note("solve", f"agent: {thought}")

        if tool == "submit":
            cand = str(action.get("flag", ""))
            flags = _flags(ctx, cand)
            if flags:
                steps.append(f"agentic loop recovered the flag after {i + 1} step(s)")
                return flags[0], steps
            history.append(f"SYSTEM: '{cand}' does not match {ctx.challenge.flag_format}; keep going.")
            continue

        inp = str(action.get("input", ""))
        if tool not in ("shell", "python") or not inp.strip():
            history.append("SYSTEM: use tool shell|python with a non-empty input, or submit.")
            continue

        # loop detection: the same action twice is a dead end -- don't burn a sandbox run on it
        sig = f"{tool}:{inp.strip()[:300]}"
        seen[sig] = seen.get(sig, 0) + 1
        if seen[sig] >= 2:
            ctx.trace.note("solve", "agent loop detected — nudging a different approach")
            history.append("SYSTEM: you already ran that exact action with the same result. "
                           "STOP repeating it. Try a COMPLETELY different tool or technique.")
            continue

        try:
            out, flags = await _run_action(ctx, i, tool, inp)
        except Exception as exc:
            history.append(f"{tool}: {inp[:160]}\n-> error: {exc}")
            continue

        if flags:
            steps.append(f"agentic loop recovered the flag via {tool} at iter {i + 1}")
            return flags[0], steps

        steps.append(f"agent {tool} (iter {i + 1}): no flag yet")
        history.append(f"{tool}: {inp[:200]}\n-> {out[:1200]}")

    if not steps:
        steps.append("agentic loop made no progress")
    return None, steps
