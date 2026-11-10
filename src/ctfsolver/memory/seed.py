"""Seed the procedural memory (technique library) from the bundled JSON.

The technique library is the system's compounding moat: CTF techniques repeat
heavily across events. This module loads ``data/techniques.json`` from the repo
root (stdlib only, offline) and inserts each entry as a :class:`Technique`.

It is deliberately forgiving -- a malformed entry is skipped rather than aborting
the whole seed, and a missing file yields 0 so importing/seeding never crashes a
fresh install.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import Category, Technique

# repo_root/data/techniques.json, resolved relative to THIS file:
# src/ctfsolver/memory/seed.py -> parents[3] == repo root
_DEFAULT_PATH = Path(__file__).resolve().parents[3] / "data" / "techniques.json"


def seed_techniques(store, path: Optional[str] = None) -> int:
    """Load the technique library into ``store`` and return how many were added.

    ``store`` is anything exposing ``add_technique(Technique) -> id`` (the
    :class:`~ctfsolver.memory.store.MemoryStore`). ``path`` overrides the default
    ``repo_root/data/techniques.json`` location.

    Robustness contract:
      * missing file           -> return 0
      * invalid top-level JSON  -> return 0
      * malformed entry         -> skipped, others still loaded
    """
    json_path = Path(path) if path else _DEFAULT_PATH

    try:
        raw = json_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return 0

    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return 0

    if not isinstance(entries, list):
        return 0

    count = 0
    for entry in entries:
        technique = _build_technique(entry)
        if technique is None:
            continue
        try:
            store.add_technique(technique)
        except Exception:
            # A single bad insert must not sink the rest of the seed.
            continue
        count += 1
    return count


def _build_technique(entry) -> Optional[Technique]:
    """Turn one JSON object into a :class:`Technique`, or ``None`` if unusable."""
    if not isinstance(entry, dict):
        return None

    title = entry.get("title")
    category_value = entry.get("category")
    if not title or not category_value:
        return None

    try:
        category = Category(str(category_value).strip().lower())
    except ValueError:
        return None

    tags = entry.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    tags = [str(t) for t in tags]

    return Technique(
        title=str(title),
        category=category,
        pattern=str(entry.get("pattern", "")),
        recipe=str(entry.get("recipe", "")),
        tags=tags,
        source=str(entry.get("source", "seed")),
    )
