"""Models + intake: parsing a target or a file into a Challenge."""
from __future__ import annotations

import os
import tempfile

from ctfsolver.models import Category, Outcome, OutcomeStatus, Target
from ctfsolver.pipeline.intake import classify_artifact, intake, parse_target


def test_category_coerce():
    assert Category.coerce("PWN") is Category.PWN
    assert Category.coerce("nonsense") is Category.UNKNOWN


def test_target_scope_key_and_parse():
    assert parse_target("nc host.ctf 1337") == Target("tcp", "host.ctf", 1337, raw="nc host.ctf 1337")
    assert parse_target("host.ctf:9001").kind == "tcp"
    t = parse_target("https://web.ctf/app")
    assert t.kind == "http" and t.url == "https://web.ctf/app"
    assert parse_target("plain.ctf").kind == "tcp"


def test_outcome_solved_flag():
    o = Outcome(OutcomeStatus.SOLVED)
    assert not o.solved  # no flag -> not solved
    from ctfsolver.models import Flag

    o.flag = Flag("flag{x}")
    assert o.solved


def test_classify_artifact_elf_and_text():
    with tempfile.TemporaryDirectory() as d:
        elf = os.path.join(d, "vuln")
        with open(elf, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 60)
        a = classify_artifact(elf)
        assert a.kind == "binary" and a.sha256

        txt = os.path.join(d, "cipher.b64")
        with open(txt, "wb") as f:
            f.write(b"QUJDREVG")
        assert classify_artifact(txt).kind == "text"


def test_intake_infers_category():
    with tempfile.TemporaryDirectory() as d:
        elf = os.path.join(d, "vuln")
        with open(elf, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 60)
        c = intake("pwnme", targets=["nc host 1337"], files=[elf])
        assert c.category_hint is Category.PWN
        assert c.scope_keys == ["host:1337"]

    web = intake("webby", targets=["https://site.ctf/"])
    assert web.category_hint is Category.WEB
