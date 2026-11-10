"""Rev specialist.

Decompilation and symbolic execution need ghidra/angr/radare2 in the container sandbox.
Offline this specialist runs a broadened static pass that solves a real slice of easy
challenges on its own: it scans every artifact for the flag format directly, then pulls
out printable strings and re-checks any that look base64-ish or suspiciously
high-entropy by *decoding* them and looking again for a flag. When nothing falls out it
lays out a concrete ghidra/angr plan -- optionally re-ranked by
`ctx.llm('solve_strategy')` -- and BLOCKS cleanly for the container sandbox.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from typing import Optional

from ..llm.base import Message, extract_json
from ..models import Category, Outcome
from .base import SolveContext, Specialist
from .registry import register
from .runner import llm_write_and_run, run_provided

# Printable ASCII runs of length >= 4, the classic `strings` heuristic.
_STRINGS_RE = re.compile(rb"[\x20-\x7e]{4,}")
# Candidates worth trying to base64-decode.
_B64ISH_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")


def _shannon_entropy(data: bytes) -> float:
    """Bits per byte. High entropy (>4.0 over printable text) hints at encoding/packing."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _iter_strings(data: bytes, limit: int = 4000):
    """Yield printable strings from a blob, capped so a huge binary can't stall us."""
    for i, m in enumerate(_STRINGS_RE.finditer(data)):
        if i >= limit:
            break
        yield m.group(0).decode("ascii", "ignore")


def _maybe_b64_decode(s: str) -> Optional[bytes]:
    if not _B64ISH_RE.match(s):
        return None
    # require balanced-ish length so we don't try every random token
    if len(s) % 4 != 0 and "=" not in s:
        return None
    try:
        out = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    return out or None


@register
class RevSpecialist(Specialist):
    category = Category.REV
    name = "rev-specialist"

    def fit_bonus(self, challenge, understanding) -> float:
        text = " ".join(understanding.recon + [understanding.subtype]).lower()
        hot = ("elf", "binary", "crackme", "keygen", "license", "disassemble", "decompile")
        return 0.15 if any(k in text for k in hot) else 0.0

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format
        steps: list[str] = []
        entropy_notes: list[str] = []

        for art in ctx.challenge.artifacts:
            try:
                data = ctx.sandbox.read_bytes(art.name)
            except OSError as exc:
                steps.append(f"read {art.name} -> error: {exc}")
                continue

            # 1) flag sitting in the open (latin-1 so every byte maps to a char).
            for flag in self.find_flags(data.decode("latin-1"), fmt):
                steps.append(f"strings {art.name} -> flag")
                return self.found(flag, f"embedded string in {art.name}", steps, cost_usd=0.0)

            ent = _shannon_entropy(data)
            entropy_notes.append(f"{art.name}: entropy {ent:.2f} bits/byte")

            # 2) broadened static pass: decode base64-looking / high-entropy strings
            #    and re-check for a flag (a very common easy-rev trick). Each extracted
            #    string is also split on whitespace so a base64 token embedded in a
            #    larger printable run is still isolated and tried.
            decoded_hits = 0
            seen: set[str] = set()
            for s in _iter_strings(data):
                for tok in (s, *s.split()):
                    if tok in seen:
                        continue
                    seen.add(tok)
                    raw = _maybe_b64_decode(tok)
                    if raw is None:
                        continue
                    decoded_hits += 1
                    text = raw.decode("utf-8", "ignore")
                    for flag in self.find_flags(text, fmt):
                        steps.append(f"strings {art.name} -> base64 string -> decode -> flag")
                        return self.found(
                            flag, f"base64-encoded string in {art.name}", steps,
                            used_technique_ids=self._credit(ctx, "base64-embedded-string"))
            if decoded_hits:
                steps.append(f"strings {art.name} -> decoded {decoded_hits} base64-ish token(s), no flag")
            else:
                steps.append(f"strings {art.name} -> nothing obvious")

        if entropy_notes:
            steps.append("entropy: " + "; ".join(entropy_notes))
            if any(float(n.split()[-2]) > 4.5 for n in entropy_notes if len(n.split()) >= 2):
                steps.append("note: high entropy -> likely packed/encrypted; try upx -d or "
                             "a runtime dump before static analysis")

        # 3) LIVE: in a real container, run the provided target (a crackme may print the
        # flag, or reveal the check) and let the model write an angr/z3 solver.
        if ctx.sandbox.isolated and ctx.challenge.artifacts:
            art = ctx.challenge.artifacts[0]
            res, flags = await run_provided(ctx, art.name, timeout=30)
            if res is not None:
                steps.append(f"ran ./{art.name} (rc={res.returncode})")
                if flags:
                    return self.found(flags[0], f"running provided {art.name}", steps)
            prompt = (
                "Write a COMPLETE standalone Python 3 solver (angr and/or z3, stdlib) for a "
                "CTF reversing challenge. Read the binary path from sys.argv[1]; find the "
                "input that makes it accept and print the flag (flag{...}) to stdout. Code only.\n"
                f"Binary: {art.name}\nRecon: {'; '.join(ctx.understanding.recon[:6])}\n"
            )
            _res, flags, note = await llm_write_and_run(
                ctx, "solve_strategy", prompt,
                system="Expert reverse engineer. Reply with Python code only.",
                filename="rev_solve.py", args=[art.name], timeout=120)
            steps.append(note)
            if flags:
                return self.found(flags[0], "model-written angr/z3 solver run in the container", steps)

        # 4) static-analysis plan, optionally re-ranked by the frontier model.
        plan = self._plan(ctx)
        strat = await self._ask_strategy(ctx, entropy_notes)
        if strat:
            plan = strat + plan
        for p in plan:
            steps.append(f"plan: {p}")

        return self.blocked(
            "reversing needs the container sandbox (ghidra/angr/radare2); offline "
            "strings+decode pass is complete and the analysis plan is ready.",
            steps, hint="enable the container sandbox")

    # ------------------------------------------------------------------ #
    def _plan(self, ctx: SolveContext) -> list[str]:
        recalled = [t.title for t in ctx.techniques] or ["(no matching technique recalled)"]
        return [
            "file/strings/nm recon; identify language, packer, and the check function",
            f"recalled techniques: {', '.join(recalled)}",
            "load in ghidra (headless) or radare2; locate the input->compare logic",
            "recover the constraint(s) on the accepted input",
            "solve with angr (symbolic) or z3 (SMT); reconstruct the input -> flag",
        ]

    async def _ask_strategy(self, ctx: SolveContext, entropy_notes: list[str]) -> list[str]:
        """Ask the frontier model to rank reversing avenues. Guarded by affordability;
        tolerant of stub/garbage replies (never raises)."""
        if not ctx.ledger.can_afford(0.004, 1):
            return []
        names = [a.name for a in ctx.challenge.artifacts] or ["<binary>"]
        prompt = (
            "You are triaging a CTF reversing challenge. Rank the most promising static "
            "and symbolic approaches as JSON: {\"ranking\": [\"...\", \"...\"]}.\n"
            f"Artifacts: {names}\n"
            f"Entropy: {entropy_notes or 'unknown'}\n"
            f"Description: {ctx.challenge.description[:300]!r}\n"
        )
        try:
            client = ctx.llm("solve_strategy")
            resp = await client.complete(
                [Message("user", prompt)],
                system="Terse CTF reversing strategist. Reply with JSON only.",
            )
        except Exception as exc:
            return [f"(strategy model unavailable: {exc})"]
        return _fold_strategy(resp.text)

    def _credit(self, ctx: SolveContext, tag: str) -> list[str]:
        for t in ctx.techniques:
            if tag in (t.tags or []) or tag in t.title.lower():
                return [t.id]
        return []


def _fold_strategy(text: str) -> list[str]:
    """Parse an LLM strategy reply defensively into step strings. Never raises."""
    if not text or not text.strip():
        return []
    ranked: list[str] = []
    try:
        parsed = extract_json(text)
    except Exception:
        parsed = None

    def _collect(obj) -> None:
        if isinstance(obj, str):
            s = obj.strip()
            if s:
                ranked.append(s)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item)
        elif isinstance(obj, dict):
            for key in ("ranking", "strategies", "plan", "approaches", "steps"):
                if key in obj:
                    _collect(obj[key])

    if parsed is not None:
        _collect(parsed)

    if not ranked:
        for line in text.splitlines():
            line = line.strip(" -*\t")
            if line and not line.startswith("{") and not line.startswith("}"):
                ranked.append(line)
            if len(ranked) >= 5:
                break

    return [f"LLM strategy: {r}" for r in ranked[:5]]
