"""Forensics specialist.

pcap/memory/disk work needs tshark/volatility3/binwalk in the container sandbox.
Offline this specialist carves the raw bytes for an exposed flag (the cheap win that
cracks many stego / strings-in-capture challenges), *detects each artifact's type from
its magic bytes*, and branches its plan accordingly (binwalk for images/archives, tshark
for captures, volatility3 for memory dumps). The plan is optionally re-ranked by
`ctx.llm('solve_strategy')` before it BLOCKS cleanly for the container sandbox.
"""
from __future__ import annotations

from typing import Optional

from ..llm.base import Message, extract_json
from ..models import Category, Outcome
from .base import SolveContext, Specialist
from .registry import register
from .runner import llm_write_and_run


def _detect_type(head: bytes) -> tuple[str, str]:
    """Return (type, plan-hint) from the first bytes of an artifact.

    Pure magic-byte sniffing -- no libmagic, no network, no filesystem probing beyond
    the bytes already read."""
    if not head:
        return "empty", "no bytes to analyze"
    # Image formats
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image: zsteg/binwalk/exiftool; check LSB stego & appended data"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg", "image: binwalk/steghide/exiftool; check trailing data after EOI (FFD9)"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif", "image: split frames; check per-frame & appended data"
    if head.startswith(b"BM"):
        return "bmp", "image: LSB stego; raw pixel inspection"
    # Archives / containers
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip", "archive: unzip; check for password, nested/polyglot, zip-slip"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar", "archive: unrar; check comment/recovery records"
    if head.startswith(b"\x1f\x8b"):
        return "gzip", "archive: gunzip then re-scan the inner stream"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z", "archive: 7z x; inspect contents"
    # Packet captures
    if head.startswith(b"\xd4\xc3\xb2\xa1") or head.startswith(b"\xa1\xb2\xc3\xd4"):
        return "pcap", "capture: tshark/wireshark; follow TCP/HTTP streams, export objects"
    if head.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng", "capture: tshark (pcapng); follow streams, export objects"
    # Executables (often a dropped/embedded payload in forensics)
    if head.startswith(b"\x7fELF"):
        return "elf", "executable: hand to rev; strings/ghidra; may be a dropped payload"
    if head.startswith(b"MZ"):
        return "pe", "executable: PE triage; check for embedded resources/overlay"
    # Documents / disk / memory heuristics
    if head.startswith(b"%PDF-"):
        return "pdf", "document: pdf-parser/peepdf; check JS, objects, embedded files"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole", "document/registry: olevba/oletools; check macros & streams"
    if head.startswith(b"\x53\xff\x00\xf0\x53\xff\x00\xf0"):
        return "memory", "memory dump: volatility3; identify OS profile, pslist/filescan"
    if head.startswith(b"EMiL") or head.startswith(b"PAGEDUMP") or head.startswith(b"PAGEDU64"):
        return "memory", "memory dump (crashdump): volatility3 windows.info then pslist"
    # Filesystem / disk images
    if len(head) > 514 and head[510:512] == b"\x55\xaa":
        return "diskimage", "disk image: mmls/fls (sleuthkit); carve partitions with binwalk"
    return "unknown", "unknown type: binwalk --entropy, foremost carve, strings sweep"


@register
class ForensicsSpecialist(Specialist):
    category = Category.FORENSICS
    name = "forensics-specialist"

    def fit_bonus(self, challenge, understanding) -> float:
        text = " ".join(understanding.recon + [understanding.subtype]).lower()
        hot = ("pcap", "capture", "stego", "memory", "volatility", "disk", "image", "wireshark")
        return 0.15 if any(k in text for k in hot) else 0.0

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format
        steps: list[str] = []
        detected: list[tuple[str, str, str]] = []  # (artifact, type, hint)

        for art in ctx.challenge.artifacts:
            try:
                data = ctx.sandbox.read_bytes(art.name)
            except OSError as exc:
                steps.append(f"read {art.name} -> error: {exc}")
                continue

            # 1) cheap win: flag carved straight from the raw bytes.
            for flag in self.find_flags(data.decode("latin-1"), fmt):
                steps.append(f"carve {art.name} -> flag in bytes")
                return self.found(flag, f"raw bytes of {art.name}", steps, cost_usd=0.0)

            # 2) magic-byte type detection -> per-type plan branch.
            atype, hint = _detect_type(data[:64])
            detected.append((art.name, atype, hint))
            steps.append(f"magic {art.name} -> {atype}")

        for name, atype, hint in detected:
            steps.append(f"plan[{name} = {atype}]: {hint}")

        # 3) LIVE: a generated pure-Python extraction/carve solver can run even on the
        # offline sandbox (it only reads the provided artifact). Try it before blocking.
        if ctx.challenge.artifacts:
            art = ctx.challenge.artifacts[0]
            atype = next((t for n, t, _ in detected if n == art.name), "unknown")
            prompt = (
                "Write a COMPLETE standalone Python 3 script (stdlib only) that extracts a "
                "hidden CTF flag (format flag{...}) from a file and prints it to stdout. "
                "Read the path from sys.argv[1]. Try: trailing/appended data after the "
                "format's end marker, LSB of bytes, zlib-decompressing embedded streams, and "
                "a strings sweep. Code only.\n"
                f"File: {art.name} (detected type: {atype})\n"
            )
            _res, flags, note = await llm_write_and_run(
                ctx, "solve_scripting", prompt,
                system="Expert digital forensics analyst. Reply with Python code only.",
                filename="forensics_solve.py", args=[art.name], timeout=90)
            steps.append(note)
            if flags:
                return self.found(flags[0], "generated extraction solver run in the sandbox", steps)

        # 4) overall plan, optionally re-ranked by the frontier model.
        plan = self._plan(detected)
        strat = await self._ask_strategy(ctx, detected)
        if strat:
            plan = strat + plan
        for p in plan:
            steps.append(f"plan: {p}")

        return self.blocked(
            "forensics needs the container sandbox (tshark/volatility3/binwalk); offline "
            "byte-carve + magic-byte typing is complete and the per-artifact plan is ready.",
            steps, hint="enable the container sandbox")

    # ------------------------------------------------------------------ #
    def _plan(self, detected: list[tuple[str, str, str]]) -> list[str]:
        types = {t for _, t, _ in detected}
        plan: list[str] = []
        if types & {"png", "jpg", "gif", "bmp"}:
            plan.append("stego sweep: binwalk/zsteg/steghide + exiftool + appended-data check")
        if types & {"pcap", "pcapng"}:
            plan.append("capture: tshark follow streams, export HTTP/SMB objects, decode creds")
        if "memory" in types:
            plan.append("memory: volatility3 -- OS profile, pslist/cmdline/filescan/dumpfiles")
        if types & {"zip", "rar", "gzip", "7z"}:
            plan.append("archive: extract (crack password if needed), recurse into contents")
        if "diskimage" in types:
            plan.append("disk: sleuthkit mmls/fls/icat, recover deleted files, carve slack space")
        # always-applicable fallbacks
        plan += [
            "binwalk --entropy + foremost/photorec to carve embedded artifacts",
            "extract the embedded/hidden artifact and re-scan it -> flag",
        ]
        return plan

    async def _ask_strategy(self, ctx: SolveContext,
                            detected: list[tuple[str, str, str]]) -> list[str]:
        """Ask the frontier model to rank forensic avenues. Guarded by affordability;
        tolerant of stub/garbage replies (never raises)."""
        if not ctx.ledger.can_afford(0.004, 1):
            return []
        summary = [f"{n}:{t}" for n, t, _ in detected] or ["<no artifacts>"]
        prompt = (
            "You are triaging a CTF forensics challenge. Rank the most promising "
            "extraction avenues as JSON: {\"ranking\": [\"...\", \"...\"]}.\n"
            f"Detected artifacts (name:type): {summary}\n"
            f"Description: {ctx.challenge.description[:300]!r}\n"
        )
        try:
            client = ctx.llm("solve_strategy")
            resp = await client.complete(
                [Message("user", prompt)],
                system="Terse CTF forensics strategist. Reply with JSON only.",
            )
        except Exception as exc:
            return [f"(strategy model unavailable: {exc})"]
        return _fold_strategy(resp.text)


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
            for key in ("ranking", "strategies", "plan", "avenues", "steps"):
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
