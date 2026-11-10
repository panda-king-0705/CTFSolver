"""Scoreboard submission adapters (CTFd / rCTF / generic HTTP), tested offline with an
injected transport: request shape, verdict parsing, rate-limit retry, and that the token
never reaches the trace."""
from __future__ import annotations

import asyncio
import json

from ctfsolver.models import Challenge, Flag, Submission
from ctfsolver.pipeline.checkers import (
    CTFdChecker,
    HTTPChecker,
    RCTFChecker,
    build_checker,
)
from ctfsolver.pipeline.verify import verify
from ctfsolver.trace import Trace


class FakeTransport:
    """Records each call and returns queued responses (last response repeats)."""

    def __init__(self, *responses):
        self.responses = list(responses) or [(200, {})]
        self.calls: list[dict] = []
        self.i = 0

    def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        status, obj = self.responses[min(self.i, len(self.responses) - 1)]
        self.i += 1
        return status, obj if isinstance(obj, str) else json.dumps(obj)


def _chal() -> Challenge:
    return Challenge(name="c", flag_format=r"flag\{[^}]+\}")


# ------------------------------- CTFd ------------------------------------- #
def test_ctfd_correct_request_shape():
    ft = FakeTransport((200, {"success": True, "data": {"status": "correct"}}))
    chk = CTFdChecker("https://ctf.example/", 42, token="tok", transport=ft)
    ok, detail = asyncio.run(chk.submit("flag{x}", _chal()))
    assert ok and detail == "correct"
    call = ft.calls[0]
    assert call["url"] == "https://ctf.example/api/v1/challenges/attempt"
    assert call["body"] == {"challenge_id": 42, "submission": "flag{x}"}
    assert call["headers"]["Authorization"] == "Token tok"


def test_ctfd_incorrect_and_already_solved():
    inc = CTFdChecker("https://x", 1, transport=FakeTransport((200, {"data": {"status": "incorrect"}})))
    assert asyncio.run(inc.submit("flag{y}", _chal())) == (False, "incorrect")
    solved = CTFdChecker("https://x", 1, transport=FakeTransport((200, {"data": {"status": "already_solved"}})))
    assert asyncio.run(solved.submit("flag{y}", _chal())) == (True, "already-solved")


def test_ctfd_ratelimit_then_correct():
    ft = FakeTransport((200, {"data": {"status": "ratelimited"}}),
                       (200, {"data": {"status": "correct"}}))
    chk = CTFdChecker("https://x", 1, transport=ft, retry_sleep=0)
    assert asyncio.run(chk.submit("flag{z}", _chal())) == (True, "correct")
    assert len(ft.calls) == 2


def test_ctfd_auth_failed_and_missing_id():
    auth = CTFdChecker("https://x", 1, transport=FakeTransport((403, {})))
    assert asyncio.run(auth.submit("flag{a}", _chal())) == (False, "auth-failed")
    noid = CTFdChecker("https://x", None, transport=FakeTransport((200, {})))
    assert asyncio.run(noid.submit("flag{a}", _chal())) == (False, "no challenge_id configured")


# ------------------------------- rCTF ------------------------------------- #
def test_rctf_good_bad_badtoken():
    good = RCTFChecker("https://r/", 7, token="t", transport=FakeTransport((200, {"kind": "goodFlag"})))
    ft = good._t
    assert asyncio.run(good.submit("flag{g}", _chal())) == (True, "correct")
    assert ft.calls[0]["url"] == "https://r/api/v1/challs/7/submit"
    assert ft.calls[0]["body"] == {"flag": "flag{g}"}
    assert ft.calls[0]["headers"]["Authorization"] == "Bearer t"

    bad = RCTFChecker("https://r", 7, transport=FakeTransport((200, {"kind": "badFlag"})))
    assert asyncio.run(bad.submit("flag{b}", _chal())) == (False, "incorrect")
    tok = RCTFChecker("https://r", 7, transport=FakeTransport((200, {"kind": "badToken"})))
    assert asyncio.run(tok.submit("flag{b}", _chal())) == (False, "auth-failed")


def test_rctf_ratelimit_retry():
    ft = FakeTransport((200, {"kind": "rateLimited"}), (200, {"kind": "goodFlag"}))
    chk = RCTFChecker("https://r", 7, transport=ft, retry_sleep=0)
    assert asyncio.run(chk.submit("flag{x}", _chal())) == (True, "correct")
    assert len(ft.calls) == 2


# --------------------------- generic HTTP --------------------------------- #
def test_http_generic_success_marker():
    ok = HTTPChecker("https://s/submit", success_contains="correct",
                     transport=FakeTransport((200, "well done, correct!")))
    assert asyncio.run(ok.submit("flag{x}", _chal())) == (True, "correct")
    bad = HTTPChecker("https://s/submit", transport=FakeTransport((500, "err")))
    assert asyncio.run(bad.submit("flag{x}", _chal())) == (False, "rejected (http-500)")


# --------------------------- factory routing ------------------------------ #
def test_build_checker_routing_and_token_env(monkeypatch):
    assert isinstance(build_checker(Submission(kind="ctfd", endpoint="x", challenge_id=1)), CTFdChecker)
    assert isinstance(build_checker(Submission(kind="rctf", endpoint="x", challenge_id=1)), RCTFChecker)
    assert isinstance(build_checker(Submission(kind="http", endpoint="x")), HTTPChecker)
    assert build_checker(Submission(kind="none")) is None
    assert build_checker(Submission(kind="regex", extra={"answer": "flag{a}"})) is None

    monkeypatch.setenv("MY_CTF_TOKEN", "secret-from-env")
    chk = build_checker(Submission(kind="ctfd", endpoint="x", challenge_id=1,
                                   extra={"token_env": "MY_CTF_TOKEN"}))
    assert chk.token == "secret-from-env"


# ------------------- verify integration + no token leak ------------------- #
def test_verify_submits_and_never_logs_token():
    chal = Challenge(
        name="c", flag_format=r"flag\{[^}]+\}",
        submission=Submission(kind="ctfd", endpoint="https://ctf", challenge_id=5,
                              extra={"token": "SECRET123"}),
    )
    checker = CTFdChecker("https://ctf", 5, token="SECRET123",
                          transport=FakeTransport((200, {"data": {"status": "correct"}})))
    tr = Trace(chal.id)
    accepted, rec = asyncio.run(verify(Flag("flag{win}"), chal, tr, checker=checker))
    assert accepted and rec["checker"] == "ctfd"
    # the token must never appear anywhere in the trace
    dumped = "\n".join(e.to_json() for e in tr.events)
    assert "SECRET123" not in dumped
    assert "flag{win}" in dumped  # the flag itself is fine to log
