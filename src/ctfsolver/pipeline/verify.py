"""Verify: the flag is the oracle. A candidate is accepted only if it matches the
challenge's flag format and (when one exists) is accepted by the challenge's checker.
This is objective and cheap -- the Brain's separate judge-model collapses to a regex and
a submit. The empty-done guard refuses a 'solved' with no flag."""
from __future__ import annotations

import re
from typing import Any, Optional, Protocol

from ..models import Challenge, Flag
from ..trace import Trace
from .checkers import build_checker


class Checker(Protocol):
    name: str

    async def submit(self, flag_value: str, challenge: Challenge) -> tuple[bool, str]: ...


class StubChecker:
    """Offline checker: the regex match already happened, so it accepts. Used when the
    challenge carries no real scoreboard (set submission.kind to ctfd/rctf/http for that)."""

    name = "stub"

    async def submit(self, flag_value: str, challenge: Challenge) -> tuple[bool, str]:
        return True, "stub-accepted"


class RegexChecker:
    """A self-contained checker: the flag is correct iff it equals a known value or
    matches an exact pattern carried in submission.extra['answer'] / ['pattern']."""

    name = "regex"

    async def submit(self, flag_value: str, challenge: Challenge) -> tuple[bool, str]:
        extra = challenge.submission.extra or {}
        answer = extra.get("answer")
        if answer is not None:
            return (flag_value == answer), ("exact-match" if flag_value == answer else "wrong")
        pattern = extra.get("pattern")
        if pattern:
            ok = re.fullmatch(pattern, flag_value) is not None
            return ok, ("pattern-match" if ok else "pattern-miss")
        return True, "no-answer-configured"


def get_checker(challenge: Challenge) -> Optional[Checker]:
    sub = challenge.submission
    if sub.kind in ("ctfd", "rctf", "http"):
        chk = build_checker(sub)
        if chk is not None:
            return chk
    if sub.kind in ("none", "regex"):
        return RegexChecker() if (sub.extra or {}) else StubChecker()
    return StubChecker()


async def verify(
    flag: Optional[Flag],
    challenge: Challenge,
    trace: Trace,
    *,
    checker: Optional[Checker] = None,
) -> tuple[bool, dict[str, Any]]:
    with trace.span("verify"):
        # empty-done guard
        if flag is None or not flag.value:
            trace.note("verify", "no flag -> rejected (empty-done guard)")
            return False, {"reason": "no flag"}
        # format gate
        try:
            if re.fullmatch(challenge.flag_format, flag.value) is None and not re.search(
                challenge.flag_format, flag.value
            ):
                trace.note("verify", f"format mismatch: {flag.value!r}")
                return False, {"reason": "format mismatch", "flag": flag.value}
        except re.error:
            pass
        # checker submission (the ground truth when present). The checker talks to the
        # operator-configured scoreboard; tokens stay inside it and never reach the trace.
        chk = checker or get_checker(challenge)
        cname = getattr(chk, "name", type(chk).__name__)
        trace.note("verify", f"submitting to checker={cname}")
        accepted, detail = await chk.submit(flag.value, challenge)
        # Honesty: "verified" means a REAL checker (scoreboard / known answer) confirmed it.
        # The stub only confirms the flag FORMAT -- that is format-valid, not verified, and must
        # never be presented as verified. The flag still counts as a solve offline (accepted).
        real_checker = cname != "stub"
        flag.verified = accepted and real_checker
        if accepted and not real_checker:
            trace.note("verify", f"format-valid (no scoreboard; not verified): {flag.value}")
        trace.emit("verify", "flag" if accepted else "note", flag.value,
                   accepted=accepted, verified=flag.verified, detail=detail, checker=cname)
        return accepted, {"reason": detail, "flag": flag.value, "checker": cname,
                          "verified": flag.verified, "format_valid": accepted}
