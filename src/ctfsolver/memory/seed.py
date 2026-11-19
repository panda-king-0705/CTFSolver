"""Seed the procedural memory (technique library) from the bundled JSON.

The technique library is the system's compounding moat: CTF techniques repeat
heavily across events. This module loads every ``data/techniques*.json`` file
from the repo root (stdlib only, offline) and inserts each entry as a
:class:`Technique`. The split lets curated reference material -- e.g. the
web-and-CTF concept reference distilled into solve skeletons
(``data/techniques_web_ctf.json``) -- ride the same retrieval pipeline the
specialists already pull from, without any extra wiring.

It is deliberately forgiving -- a malformed entry is skipped rather than aborting
the whole seed, and a missing file yields 0 so importing/seeding never crashes a
fresh install.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import Category, Technique

# repo_root/data/, resolved relative to THIS file:
# src/ctfsolver/memory/seed.py -> parents[3] == repo root
_DATA_DIR = Path(__file__).resolve().parents[3] / "data"
_DEFAULT_PATH = _DATA_DIR / "techniques.json"


def _library_paths() -> list[Path]:
    """All bundled technique files, with the canonical ``techniques.json`` first so
    its entries win any title collision (dedupe is first-wins)."""
    try:
        extras = sorted(p for p in _DATA_DIR.glob("techniques*.json") if p != _DEFAULT_PATH)
    except OSError:
        extras = []
    return ([_DEFAULT_PATH] if _DEFAULT_PATH.exists() else []) + extras


def seed_techniques(store, path: Optional[str] = None) -> int:
    """Load the technique library into ``store`` and return how many were added.

    ``store`` is anything exposing ``add_technique(Technique) -> id`` (the
    :class:`~ctfsolver.memory.store.MemoryStore`). ``path`` loads a single file;
    when omitted, every ``repo_root/data/techniques*.json`` file is loaded.

    Entries are de-duplicated by (case-insensitive) title, first file wins, so the
    canonical ``techniques.json`` stays authoritative over the reference packs.

    Robustness contract:
      * missing file           -> contributes 0
      * invalid top-level JSON  -> contributes 0
      * malformed entry         -> skipped, others still loaded
    """
    paths = [Path(path)] if path else _library_paths()

    count = 0
    seen_titles: set[str] = set()
    for json_path in paths:
        for entry in _load_entries(json_path):
            technique = _build_technique(entry)
            if technique is None:
                continue
            key = technique.title.strip().lower()
            if key in seen_titles:
                continue
            try:
                store.add_technique(technique)
            except Exception:
                # A single bad insert must not sink the rest of the seed.
                continue
            seen_titles.add(key)
            count += 1
    return count


def _load_entries(json_path: Path) -> list:
    """Parse one technique file into a list of raw entries; [] on any failure."""
    try:
        raw = json_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return []
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    return entries if isinstance(entries, list) else []


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
