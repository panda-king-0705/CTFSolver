"""Misc / recon specialist.

The catch-all. Offline it is genuinely useful: it scans every artifact for an exposed
flag (strings-style), walks an encoding ladder, and inspects any provided description.
Harder misc (esoteric langs, scripting puzzles) is where `ctx.llm('solve_strategy')`
writes and the sandbox runs a solver script.
"""
from __future__ import annotations

import base64
import binascii
import codecs

from ..models import Category, Outcome
from .base import SolveContext, Specialist
from .registry import register


def _decodings(data: bytes):
    yield "raw", data
    s = data.strip()
    try:
        yield "base64", base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        yield "base32", base64.b32decode(s, casefold=True)
    except (binascii.Error, ValueError):
        pass
    try:
        yield "hex", bytes.fromhex(s.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        yield "rot13", codecs.encode(data.decode("utf-8", "ignore"), "rot_13").encode()
    except Exception:
        pass


@register
class MiscSpecialist(Specialist):
    category = Category.MISC
    name = "misc-specialist"

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format
        steps: list[str] = []

        # description can carry it directly in trivial challenges
        for flag in self.find_flags(ctx.challenge.description, fmt):
            return self.found(flag, "challenge description", steps)

        for art in ctx.challenge.artifacts:
            try:
                data = ctx.sandbox.read_bytes(art.name)
            except OSError as exc:
                steps.append(f"read {art.name} -> {exc}")
                continue
            steps.append(f"scan {art.name} ({len(data)} bytes)")
            for how, decoded in _decodings(data):
                for flag in self.find_flags(decoded.decode("utf-8", "ignore"), fmt):
                    src = f"{how} of {art.name}" if how != "raw" else f"strings of {art.name}"
                    if how != "raw":
                        steps.append(f"decode {how} -> flag")
                    return self.found(flag, src, steps)

        return self.failed("no flag via strings/encoding ladder; may need a solver script "
                           "or a different category", steps)
