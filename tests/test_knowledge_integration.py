"""The web-and-CTF concept reference (docs/WEB_AND_CTF_CONCEPTS.md), distilled into
``data/techniques_web_ctf.json``, must ride the same procedural-recall pipeline the
specialists already pull from. These tests assert it loads, de-dupes against the
canonical library, and -- the point of the whole exercise -- that a realistic triage
query surfaces the *right* playbook as the top hit, not just any same-category entry.
"""
from __future__ import annotations

import json
from pathlib import Path

from ctfsolver.memory.seed import seed_techniques
from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Category

_REPO = Path(__file__).resolve().parents[1]
_REF = _REPO / "data" / "techniques_web_ctf.json"


def _mem() -> MemoryStore:
    m = MemoryStore(":memory:")
    seed_techniques(m)
    return m


def test_reference_pack_is_valid_json_with_known_categories():
    entries = json.loads(_REF.read_text(encoding="utf-8"))
    assert isinstance(entries, list) and len(entries) >= 30
    valid = {c.value for c in Category}
    for e in entries:
        assert e["title"] and e["category"] in valid
        assert e["recipe"] and e["pattern"]  # a skeleton needs both when and how
        assert e.get("source") == "web-ctf-concepts"


def test_seed_merges_reference_and_dedupes_titles():
    m = _mem()
    total = m.conn.execute("SELECT count(*) c FROM techniques").fetchone()["c"]
    # canonical (25) + reference pack (>=36), minus nothing because titles are distinct
    assert total >= 55
    dups = m.conn.execute(
        "SELECT lower(title) t, count(*) c FROM techniques GROUP BY t HAVING c > 1"
    ).fetchall()
    assert dups == []
    # the reference lifts web coverage from a handful to broad
    web = m.conn.execute(
        "SELECT count(*) c FROM techniques WHERE category='web'"
    ).fetchone()["c"]
    assert web >= 30


def test_explicit_path_loads_only_that_file():
    m = MemoryStore(":memory:")
    n = seed_techniques(m, path=str(_REF))
    assert n >= 30
    # nothing from the canonical pwn set leaked in via the glob
    assert all(
        "ret2libc via puts" not in t.title
        for t in m.recall_techniques("", category=Category.PWN, limit=999)
    )


def test_triage_queries_surface_the_right_playbook():
    """Each query is shaped like what triage builds ('<category> <subtype> <recon>').
    The matching reference technique must be the top-ranked recall."""
    m = _mem()
    cases = [
        ("web jwt admin token signature forge", Category.WEB, "JWT forgery"),
        ("web login form sql injection bypass", Category.WEB, "SQL injection: auth bypass"),
        ("web xss reflected search comment script", Category.WEB, "Cross-site scripting"),
        ("web ssrf fetch url internal metadata", Category.WEB, "SSRF: reach internal"),
        ("web xxe xml external entity file read", Category.WEB, "XXE"),
        ("web graphql introspection schema", Category.WEB, "GraphQL"),
        ("web prototype pollution node deep merge", Category.WEB, "Prototype pollution"),
        ("web cache deception my-account static", Category.WEB, "Web cache deception"),
        ("web file upload avatar php shell", Category.WEB, "File upload to RCE"),
        ("web host header password reset poisoning", Category.WEB, "HTTP Host header"),
        ("web request smuggling content-length chunked", Category.WEB, "request smuggling"),
        ("web command injection ping shell", Category.WEB, "OS command injection"),
        ("web race condition coupon redeem once", Category.WEB, "Race conditions"),
        ("crypto padding oracle cbc token", Category.CRYPTO, "Padding oracle"),
        ("pwn stack overflow win function ret2win", Category.PWN, "ret2win"),
    ]
    for query, cat, expected_prefix in cases:
        top = m.recall_techniques(query, category=cat, limit=1)
        assert top, f"no recall for {query!r}"
        assert top[0].title.startswith(expected_prefix) or expected_prefix in top[0].title, (
            f"{query!r} -> {top[0].title!r}, expected ~{expected_prefix!r}"
        )
