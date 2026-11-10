"""Memory store: technique recall (FTS or LIKE), episodes, concepts, working board."""
from __future__ import annotations

import time

from ctfsolver.memory.store import MemoryStore
from ctfsolver.models import Attempt, Category, Flag, Outcome, OutcomeStatus, Technique


def _mem() -> MemoryStore:
    return MemoryStore(":memory:")


def test_add_and_recall_technique():
    m = _mem()
    m.add_technique(Technique(title="ret2libc puts leak", category=Category.PWN,
                              pattern="NX, no canary, libc provided",
                              recipe="leak puts; compute base; ret2system",
                              tags=["ret2libc", "rop"]))
    m.add_technique(Technique(title="single byte xor", category=Category.CRYPTO,
                              tags=["single-byte-xor"]))
    hits = m.recall_techniques("ret2libc", category=Category.PWN)
    assert hits and hits[0].category is Category.PWN
    cr = m.recall_techniques("xor", category=Category.CRYPTO)
    assert any("xor" in t.title.lower() for t in cr)


def test_bump_win_rate():
    m = _mem()
    tid = m.add_technique(Technique(title="t", category=Category.MISC))
    m.bump_technique(tid, win=True)
    m.bump_technique(tid, win=False)
    got = m.recall_techniques("t", category=Category.MISC)[0]
    assert got.uses == 2 and got.wins == 1 and 0.4 < got.win_rate < 0.6


def test_episodes_and_working_board():
    m = _mem()
    att = Attempt(challenge_id="chal_1", specialist="crypto-specialist",
                  outcome=Outcome(OutcomeStatus.SOLVED, flag=Flag("flag{a}")),
                  ended_at=time.time())
    m.add_episode(att)
    eps = m.episodes_for("chal_1")
    assert len(eps) == 1 and eps[0]["flag"] == "flag{a}"

    m.working_set("chal_1", "offset", "72")
    assert m.working_get("chal_1", "offset") == "72"
    assert m.working_all("chal_1") == {"offset": "72"}
    m.working_clear("chal_1")
    assert m.working_all("chal_1") == {}


def test_concepts_recall():
    m = _mem()
    m.add_concept("flag_format:eventX", r"flag\{.+\}", tags=["crypto"])
    hits = m.recall_concepts("eventX")
    assert hits and "eventX" in hits[0]["key"]


def test_seed_library_loads():
    from ctfsolver.memory.seed import seed_techniques

    m = _mem()
    n = seed_techniques(m)
    assert n >= 18
    # the crypto specialist credits these tags, so they must be present
    cr = m.recall_techniques("xor base64", category=Category.CRYPTO, limit=10)
    tags = {t for tech in cr for t in tech.tags}
    assert "xor-over-base64" in tags or "single-byte-xor" in tags
