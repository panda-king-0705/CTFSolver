"""Triage: classify the challenge and gather first-contact recon before a specialist
commits effort, and recall matching techniques from memory. Rule-based and deterministic
by default; an economy-tier LLM call refines an UNKNOWN category only when affordable.
"""
from __future__ import annotations

import os
import re
from typing import Callable, Optional

from ..config import Settings
from ..llm.base import LLMClient, complete_json
from ..memory.store import MemoryStore
from ..models import Category, Challenge, Understanding
from ..trace import Trace

_B64 = re.compile(rb"^[A-Za-z0-9+/\s]+={0,2}$")
_HEX = re.compile(rb"^[0-9A-Fa-f\s]+$")


def _sniff_text(path: str) -> list[str]:
    notes: list[str] = []
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return notes
    if b"BEGIN" in head and b"KEY" in head:
        notes.append("PEM key material present (RSA/ECC)")
    stripped = head.strip()
    if stripped and _B64.match(stripped):
        notes.append("looks base64-encoded")
    elif stripped and _HEX.match(stripped) and len(stripped) > 8:
        notes.append("looks hex-encoded")
    if b"-----BEGIN PGP" in head:
        notes.append("PGP message")
    return notes


async def triage(
    challenge: Challenge,
    memory: MemoryStore,
    trace: Trace,
    llm_factory: Optional[Callable[[str], LLMClient]] = None,
    settings: Optional[Settings] = None,
    *,
    can_afford_llm: bool = False,
) -> Understanding:
    settings = settings or Settings()
    recon: list[str] = []
    subtype = ""
    category = challenge.category_hint

    with trace.span("triage", f"{challenge.name}"):
        # recon over artifacts
        for art in challenge.artifacts:
            recon.append(f"{art.name}: {art.kind}" + (f" ({art.size}B)" if art.size else ""))
            if art.kind in ("text", "source"):
                for note in _sniff_text(art.path):
                    recon.append(f"{art.name}: {note}")
                    if "base64" in note or "hex" in note:
                        subtype = subtype or "encoding"
                    if "key" in note.lower() or "RSA" in note:
                        category = Category.CRYPTO
                        subtype = "rsa"
        # recon over targets
        for t in challenge.targets:
            recon.append(f"target: {t} [{t.kind}]")

        # refine unknown category from recon keywords
        if category == Category.UNKNOWN:
            blob = " ".join(recon).lower()
            if "http" in blob:
                category = Category.WEB
            elif any(k in blob for k in ("pcap", "image", "pdf")):
                category = Category.FORENSICS
            elif "binary" in blob:
                category = Category.REV
            elif any(k in blob for k in ("base64", "hex", "key", "cipher")):
                category = Category.CRYPTO

        # optional LLM classification when still unknown and affordable
        if category == Category.UNKNOWN and can_afford_llm and llm_factory is not None:
            try:
                client = llm_factory("triage_classify")
                prompt = (
                    "Classify this CTF challenge into one of "
                    "pwn/web/rev/crypto/forensics/misc. Reply JSON {\"category\": \"...\"}.\n"
                    f"name: {challenge.name}\nrecon: {recon}\ndesc: {challenge.description[:400]}"
                )
                parsed, _ = await complete_json(client, prompt)
                category = Category.coerce(parsed.get("category", "unknown"))
                trace.note("triage", f"llm classified -> {category.value}")
            except Exception as exc:  # stub or parse failure: stay with rule-based
                trace.note("triage", f"llm classify skipped: {exc}")

        # memory recall: pull matching techniques
        query = " ".join([category.value, subtype] + recon[:3])
        techniques = memory.recall_techniques(query, category=category, limit=5)
        candidate_titles = [t.title for t in techniques]
        if candidate_titles:
            trace.note("triage", "recalled: " + "; ".join(candidate_titles[:3]))

        # confidence there is enough to act
        score = 0.5
        if category != Category.UNKNOWN:
            score += 0.2
        if challenge.artifacts or challenge.targets:
            score += 0.15
        if candidate_titles:
            score += 0.15
        score = min(1.0, score)

        u = Understanding(
            category=category, subtype=subtype, recon=recon,
            candidate_techniques=candidate_titles, score=round(score, 2),
            notes=f"hint={challenge.category_hint.value}",
        )
        trace.note("triage", f"category={category.value} subtype={subtype or '-'} score={u.score}")
        return u
