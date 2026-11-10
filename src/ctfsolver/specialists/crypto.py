"""Crypto specialist.

Fully functional offline for classic encoding/weak-cipher challenges: it walks a ladder
of transforms (base64/base32/hex decode, single-byte XOR brute force, caesar/rot) and
returns the first that yields a flag. Heavier work (RSA, lattices) is where a real
sandbox with sage/pycryptodome and `ctx.llm('solve_strategy')` take over; the structure
is identical -- recon, hypothesis from a recalled technique, build, run, check.
"""
from __future__ import annotations

import base64
import binascii
import string
from typing import Optional

from ..models import Category, Outcome
from .base import SolveContext, Specialist
from .registry import register
from .runner import llm_write_and_run, run_script

# A standalone repeating-key XOR solver the specialist WRITES into the sandbox and RUNS.
# It is the offline-demonstrable instance of the generate->run->observe loop; the same
# run_script primitive runs tool-backed solvers (sage, RsaCtfTool, pwntools) in the
# container. It recovers the key from a known-plaintext crib and decrypts.
_REPEATING_XOR_SOLVER = r'''
import re, sys
data = open(sys.argv[1], "rb").read()
crib = sys.argv[2].encode() if len(sys.argv) > 2 else b"flag{"
pat = re.compile(rb"flag\{[^}]+\}")
for klen in range(1, len(crib) + 1):
    key = bytes(data[i] ^ crib[i] for i in range(klen))
    dec = bytes(data[i] ^ key[i % klen] for i in range(min(len(crib), len(data))))
    if dec != crib[:len(dec)]:
        continue
    full = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
    m = pat.search(full)
    if m:
        print(m.group(0).decode("latin-1"))
        sys.exit(0)
print("NO FLAG")
'''

_PRINTABLE = set(bytes(string.printable, "ascii"))


def _mostly_printable(b: bytes, thresh: float = 0.9) -> bool:
    if not b:
        return False
    return sum(ch in _PRINTABLE for ch in b) / len(b) >= thresh


def _try_b64(data: bytes) -> Optional[bytes]:
    s = data.strip()
    try:
        if len(s) % 4 != 0 and b"=" not in s:
            return None
        out = base64.b64decode(s, validate=True)
        return out or None
    except (binascii.Error, ValueError):
        return None


def _try_b32(data: bytes) -> Optional[bytes]:
    try:
        return base64.b32decode(data.strip(), casefold=True) or None
    except (binascii.Error, ValueError):
        return None


def _try_hex(data: bytes) -> Optional[bytes]:
    s = data.strip()
    try:
        return bytes.fromhex(s.decode("ascii")) or None
    except (ValueError, UnicodeDecodeError):
        return None


def _xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _rot(data: bytes, n: int) -> bytes:
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append((b - 65 + n) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 + n) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


@register
class CryptoSpecialist(Specialist):
    category = Category.CRYPTO
    name = "crypto-specialist"

    def fit_bonus(self, challenge, understanding) -> float:
        text = " ".join(understanding.recon + [understanding.subtype]).lower()
        return 0.15 if any(k in text for k in ("rsa", "xor", "base64", "cipher", "aes")) else 0.0

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format
        steps: list[str] = []

        if not ctx.challenge.artifacts:
            return self.blocked(
                "crypto challenge with no artifact to work on",
                steps, hint="need the ciphertext / key file")

        for art in ctx.challenge.artifacts:
            try:
                data = ctx.sandbox.read_bytes(art.name)
            except OSError as exc:
                steps.append(f"read {art.name} -> error: {exc}")
                continue
            steps.append(f"read {art.name} ({len(data)} bytes)")

            # 1) sitting in the open?
            for flag in self.find_flags(data.decode("utf-8", "ignore"), fmt):
                return self.found(flag, f"plaintext in {art.name}", steps, cost_usd=0.0)

            # 2) single decode layer
            layers: list[tuple[str, Optional[bytes]]] = [
                ("base64", _try_b64(data)),
                ("base32", _try_b32(data)),
                ("hex", _try_hex(data)),
            ]
            for lname, decoded in layers:
                if decoded is None:
                    continue
                steps.append(f"decode {lname} -> {len(decoded)} bytes")
                for flag in self.find_flags(decoded.decode("utf-8", "ignore"), fmt):
                    return self.found(flag, f"{lname}-decode of {art.name}", steps)

                # 3) decode + single-byte XOR brute force (the toy archetype)
                hit = self._xor_brute(decoded, fmt)
                if hit:
                    key, flag = hit
                    steps.append(f"single-byte XOR key=0x{key:02x} over {lname} -> flag")
                    return self.found(
                        flag, f"{lname}-decode + xor(0x{key:02x}) of {art.name}", steps,
                        used_technique_ids=self._credit(ctx, "xor-over-base64"))

            # 4) XOR brute on raw
            hit = self._xor_brute(data, fmt)
            if hit:
                key, flag = hit
                steps.append(f"single-byte XOR key=0x{key:02x} on raw -> flag")
                return self.found(flag, f"xor(0x{key:02x}) of {art.name}", steps,
                                  used_technique_ids=self._credit(ctx, "single-byte-xor"))

            # 5) caesar / rot
            for n in range(1, 26):
                for flag in self.find_flags(_rot(data, n).decode("utf-8", "ignore"), fmt):
                    steps.append(f"rot{n} -> flag")
                    return self.found(flag, f"rot{n} of {art.name}", steps)

        # LIVE stage: the in-process ladder is exhausted, so generate a solver and RUN it
        # in the sandbox. Here: a repeating-key XOR break (which single-byte brute can't do).
        if ctx.challenge.artifacts and ctx.ledger.can_afford(0.0, 1):
            art = ctx.challenge.artifacts[0]
            res, flags = await run_script(ctx, "solve.py", _REPEATING_XOR_SOLVER, args=[art.name])
            steps.append(f"generated repeating-key-XOR solver -> python3 solve.py {art.name} "
                         f"(rc={res.returncode})")
            if flags:
                return self.found(
                    flags[0], f"generated solver (repeating-key XOR) run in the sandbox",
                    steps, used_technique_ids=self._credit(ctx, "repeating-key-xor"))

        # Last resort: ask the model to WRITE a solver from the recon, then run it.
        hit = await self._llm_solver(ctx, steps)
        if hit:
            return hit

        return self.failed(
            "classic-encoding ladder + generated solvers exhausted; likely needs heavier "
            "crypto (RSA/lattice) with sage/pycryptodome in the container sandbox", steps)

    async def _llm_solver(self, ctx: SolveContext, steps: list[str]) -> Optional[Outcome]:
        """Have the model write a standalone Python solver, then run it in the sandbox.
        Guarded by budget; tolerant of a non-code reply."""
        if not ctx.challenge.artifacts:
            return None
        art = ctx.challenge.artifacts[0]
        prompt = (
            "Write a COMPLETE standalone Python 3 solver (stdlib + pycryptodome only) for a "
            "CTF crypto challenge. It must read the ciphertext from sys.argv[1] and print the "
            f"flag (format flag{{...}}) to stdout. Output ONLY the code.\n"
            f"Recon: {'; '.join(ctx.understanding.recon[:6])}\nArtifact: {art.name}\n"
        )
        _res, flags, note = await llm_write_and_run(
            ctx, "solve_scripting", prompt,
            system="Expert CTF crypto. Reply with Python code only.",
            filename="llm_solve.py", args=[art.name])
        steps.append(note)
        if flags:
            return self.found(flags[0], "model-written solver run in the sandbox", steps)
        return None

    # ------------------------------------------------------------------ #
    def _xor_brute(self, data: bytes, fmt: str) -> Optional[tuple[int, str]]:
        for key in range(256):
            cand = _xor_single(data, key)
            if not _mostly_printable(cand, 0.6):
                continue
            flags = self.find_flags(cand.decode("utf-8", "ignore"), fmt)
            if flags:
                return key, flags[0]
        return None

    def _credit(self, ctx: SolveContext, tag: str) -> list[str]:
        for t in ctx.techniques:
            if tag in (t.tags or []) or tag in t.title.lower():
                return [t.id]
        return []
