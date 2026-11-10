"""Writeup generation -- the Learn stage's shareable output.

Every solve (and every honest dead end) becomes a reproducible markdown report: the
flag, the approach, the exact commands and the generated solver, the technique, and the
cost. Templated and deterministic by default (offline, free); an optional LLM pass can
polish the narrative. The report is built from the structured record plus the trace, so
it reflects what actually ran.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from ..models import Challenge, Outcome, Understanding
from ..trace import Trace

_LANG = {"python3": "python", "python": "python", "node": "javascript",
         "bash": "bash", "sh": "bash", "ruby": "ruby", "perl": "perl"}


def _scripts_from_trace(trace: Optional[Trace]) -> list[tuple[str, str, str]]:
    if trace is None:
        return []
    out = []
    for e in trace.events:
        if e.kind == "script":
            out.append((e.text, e.data.get("lang", "text"), e.data.get("source", "")))
    return out


def _commands_from_trace(trace: Optional[Trace]) -> list[str]:
    if trace is None:
        return []
    seen: list[str] = []
    for e in trace.events:
        if e.kind == "cmd" and e.text and e.text not in seen:
            seen.append(e.text)
    return seen


def build_writeup(
    challenge: Challenge,
    understanding: Understanding,
    outcome: Outcome,
    meta: Optional[dict[str, Any]] = None,
    *,
    trace: Optional[Trace] = None,
    author: str = "ctfsolver",
    summary: Optional[str] = None,
) -> str:
    meta = meta or {}
    solved = outcome.solved
    cat = understanding.category.value
    heading = "Writeup" if solved else "Attempt log"
    lines: list[str] = []

    # --- title + status line ---
    lines.append(f"# {challenge.name} — {cat}"
                 + (f" ({challenge.points} pts)" if challenge.points else ""))
    lines.append("")
    if solved and outcome.flag:
        lines.append(f"**Flag:** `{outcome.flag.value}`"
                     + ("  ✅ verified" if outcome.flag.verified else "  (unverified)"))
    else:
        lines.append(f"**Flag:** not recovered — status `{outcome.status.value}`")
    bits = [f"**{heading}**", f"category `{cat}`"]
    if outcome.specialist:
        bits.append(f"solver `{outcome.specialist}`")
    if "spent_usd" in meta:
        bits.append(f"cost ${meta['spent_usd']}")
    if "tool_calls" in meta:
        bits.append(f"{meta['tool_calls']} tool calls")
    lines.append(" · ".join(bits))
    lines.append("")

    # --- summary ---
    lines.append("## Summary")
    if summary:
        lines.append(summary.strip())
    elif solved and outcome.flag:
        src = outcome.flag.source or "the approach below"
        lines.append(f"Recovered the flag via {src}.")
    elif outcome.notes:
        lines.append(outcome.notes)
    else:
        lines.append(f"Challenge not solved; status `{outcome.status.value}`.")
    lines.append("")

    # --- challenge ---
    lines.append("## Challenge")
    if challenge.targets:
        lines.append(f"- Target(s): {', '.join(str(t) for t in challenge.targets)}")
    if challenge.artifacts:
        lines.append(f"- Files: {', '.join(f'`{a.name}` ({a.kind})' for a in challenge.artifacts)}")
    lines.append(f"- Flag format: `{challenge.flag_format}`")
    if challenge.description:
        lines.append("")
        lines.append(f"> {challenge.description}")
    lines.append("")

    # --- recon ---
    if understanding.recon:
        lines.append("## Recon")
        for r in understanding.recon:
            lines.append(f"- {r}")
        lines.append("")

    # --- approach ---
    if outcome.steps:
        lines.append("## Approach")
        for i, s in enumerate(outcome.steps, 1):
            lines.append(f"{i}. {s}")
        lines.append("")

    # --- commands actually run ---
    cmds = _commands_from_trace(trace)
    if cmds:
        lines.append("## Commands")
        lines.append("```sh")
        lines.extend(cmds)
        lines.append("```")
        lines.append("")

    # --- the generated solver/exploit (reproducible) ---
    scripts = _scripts_from_trace(trace)
    if scripts:
        lines.append("## Solver")
        for name, lang, source in scripts:
            lines.append(f"`{name}`:")
            lines.append(f"```{_LANG.get(lang, lang)}")
            lines.append(source.strip("\n"))
            lines.append("```")
            lines.append("")

    # --- technique ---
    if understanding.candidate_techniques:
        lines.append("## Technique")
        lines.append(f"Reached for: {', '.join(understanding.candidate_techniques[:3])}.")
        lines.append("")

    # --- open points for an unsolved challenge ---
    if not solved and outcome.hint_request:
        lines.append("## Still blocked on")
        lines.append(f"- {outcome.hint_request}")
        lines.append("")

    ts = time.strftime("%Y-%m-%d %H:%M", time.gmtime())
    lines.append("---")
    lines.append(f"*Generated by {author} · {ts} UTC*")
    return "\n".join(lines).rstrip() + "\n"


async def generate_writeup(
    challenge: Challenge,
    understanding: Understanding,
    outcome: Outcome,
    meta: Optional[dict[str, Any]] = None,
    *,
    trace: Optional[Trace] = None,
    llm=None,
    author: str = "ctfsolver",
) -> str:
    """Build the writeup. With an `llm` (and budget), replace the Summary with a short
    model-written narrative; otherwise return the deterministic template. Always falls
    back to the template on any model error."""
    if llm is None or not outcome.solved:
        return build_writeup(challenge, understanding, outcome, meta, trace=trace, author=author)
    from ..llm.base import Message

    summary = None
    try:
        prompt = (
            "Write a 2-3 sentence TL;DR for this CTF writeup (plain prose, no heading). "
            f"Challenge: {challenge.name} ({understanding.category.value}). "
            f"Flag source: {outcome.flag.source if outcome.flag else ''}. "
            f"Key steps: {'; '.join(outcome.steps[-5:])}"
        )
        resp = await llm.complete([Message("user", prompt)],
                                  system="Terse CTF writeup author. Prose only, no markdown headings.")
        text = (resp.text or "").strip()
        if text and len(text) > 20 and not text.lstrip().startswith("{"):
            summary = text  # ignore stub/JSON replies
    except Exception:
        summary = None
    return build_writeup(challenge, understanding, outcome, meta, trace=trace,
                         author=author, summary=summary)
