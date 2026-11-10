"""Scoreboard submission adapters -- the real flag oracle.

Verify submits a candidate flag to the challenge's own checker and reads the verdict.
The scoreboard is the operator-configured, trusted endpoint (not the challenge target),
so these adapters talk to it directly, separate from the sandbox's target confinement.

The HTTP transport is injectable, so request-building and response-parsing are tested
offline without a live platform. The default transport is stdlib `urllib` (no third-party
dependency). Tokens are read from config or env and never written to the trace.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Callable, Optional

from ..models import Challenge, Submission

# A transport does one request: (method, url, headers, json_body) -> (status, text).
# status == 0 signals a transport/network error (text carries the reason).
Transport = Callable[[str, str, dict, Optional[dict]], "tuple[int, str]"]


def urllib_transport(method: str, url: str, headers: dict, body: Optional[dict],
                     timeout: float = 20.0) -> "tuple[int, str]":
    import urllib.error
    import urllib.request

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def _json(text: str) -> dict:
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _resolve_token(token: Optional[str], token_env: Optional[str]) -> Optional[str]:
    if token:
        return token
    if token_env:
        return os.getenv(token_env)
    return None


# --------------------------------------------------------------------------- #
# CTFd
# --------------------------------------------------------------------------- #
class CTFdChecker:
    """CTFd: POST /api/v1/challenges/attempt {challenge_id, submission}. The response
    carries data.status in {correct, incorrect, already_solved, paused, ratelimited}."""

    name = "ctfd"

    def __init__(self, base_url: str, challenge_id: Any, *, token: Optional[str] = None,
                 token_env: Optional[str] = None, transport: Optional[Transport] = None,
                 max_retries: int = 1, retry_sleep: float = 3.0) -> None:
        self.base = (base_url or "").rstrip("/")
        self.cid = challenge_id
        self.token = _resolve_token(token, token_env)
        self._t = transport or urllib_transport
        self.max_retries = max_retries
        self.retry_sleep = retry_sleep

    async def submit(self, flag_value: str, challenge: Challenge) -> "tuple[bool, str]":
        if self.cid is None:
            return False, "no challenge_id configured"
        url = f"{self.base}/api/v1/challenges/attempt"
        headers = {"Authorization": f"Token {self.token}"} if self.token else {}
        body = {"challenge_id": self.cid, "submission": flag_value}
        attempt = 0
        while True:
            status, text = await asyncio.to_thread(self._t, "POST", url, headers, body)
            if status == 0:
                return False, f"network-error: {text[:80]}"
            if status in (401, 403):
                return False, "auth-failed"
            data = _json(text)
            st = str((data.get("data") or {}).get("status", "")).lower()
            if st == "correct":
                return True, "correct"
            if st == "already_solved":
                return True, "already-solved"
            if st == "incorrect":
                return False, "incorrect"
            if st in ("ratelimited", "paused") and attempt < self.max_retries:
                attempt += 1
                await asyncio.sleep(self.retry_sleep)
                continue
            return False, st or f"http-{status}"


# --------------------------------------------------------------------------- #
# rCTF
# --------------------------------------------------------------------------- #
class RCTFChecker:
    """rCTF: POST /api/v1/challs/<id>/submit {flag} with a Bearer token. The response
    carries kind in {goodFlag, badFlag, badChallenge, badToken, rateLimited,
    alreadySolvedChallenge}."""

    name = "rctf"

    def __init__(self, base_url: str, challenge_id: Any, *, token: Optional[str] = None,
                 token_env: Optional[str] = None, transport: Optional[Transport] = None,
                 max_retries: int = 1, retry_sleep: float = 3.0) -> None:
        self.base = (base_url or "").rstrip("/")
        self.cid = challenge_id
        self.token = _resolve_token(token, token_env)
        self._t = transport or urllib_transport
        self.max_retries = max_retries
        self.retry_sleep = retry_sleep

    async def submit(self, flag_value: str, challenge: Challenge) -> "tuple[bool, str]":
        if self.cid is None:
            return False, "no challenge_id configured"
        url = f"{self.base}/api/v1/challs/{self.cid}/submit"
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        body = {"flag": flag_value}
        attempt = 0
        while True:
            status, text = await asyncio.to_thread(self._t, "POST", url, headers, body)
            if status == 0:
                return False, f"network-error: {text[:80]}"
            kind = str(_json(text).get("kind", "")).strip()
            if kind in ("goodFlag", "alreadySolvedChallenge"):
                return True, "correct" if kind == "goodFlag" else "already-solved"
            if kind == "badFlag":
                return False, "incorrect"
            if kind == "badToken":
                return False, "auth-failed"
            if kind == "badChallenge":
                return False, "bad-challenge"
            if kind == "rateLimited" and attempt < self.max_retries:
                attempt += 1
                await asyncio.sleep(self.retry_sleep)
                continue
            if status in (401, 403):
                return False, "auth-failed"
            return False, kind.lower() or f"http-{status}"


# --------------------------------------------------------------------------- #
# Generic HTTP (escape hatch for custom scoreboards)
# --------------------------------------------------------------------------- #
class HTTPChecker:
    """POST the flag to a custom endpoint; accept iff the status matches and (optionally)
    a marker string is present in the response body."""

    name = "http"

    def __init__(self, endpoint: str, *, token: Optional[str] = None,
                 token_env: Optional[str] = None, method: str = "POST",
                 flag_field: str = "flag", success_status: int = 200,
                 success_contains: Optional[str] = None, extra_body: Optional[dict] = None,
                 headers: Optional[dict] = None, transport: Optional[Transport] = None) -> None:
        self.endpoint = endpoint
        self.token = _resolve_token(token, token_env)
        self.method = method.upper()
        self.flag_field = flag_field
        self.success_status = success_status
        self.success_contains = success_contains
        self.extra_body = extra_body or {}
        self.headers = headers or {}
        self._t = transport or urllib_transport

    async def submit(self, flag_value: str, challenge: Challenge) -> "tuple[bool, str]":
        headers = dict(self.headers)
        if self.token:
            headers.setdefault("Authorization", f"Bearer {self.token}")
        body = {self.flag_field: flag_value, **self.extra_body}
        status, text = await asyncio.to_thread(self._t, self.method, self.endpoint, headers, body)
        if status == 0:
            return False, f"network-error: {text[:80]}"
        ok = status == self.success_status and (
            self.success_contains is None or self.success_contains in text)
        return ok, "correct" if ok else f"rejected (http-{status})"


def build_checker(submission: Submission, transport: Optional[Transport] = None):
    """Build an HTTP checker from a Submission, or return None if it is not an HTTP
    platform (the caller then falls back to the format/stub checker)."""
    ex = submission.extra or {}
    kind = submission.kind
    common = dict(token=ex.get("token"), token_env=ex.get("token_env"), transport=transport)
    if kind == "ctfd":
        return CTFdChecker(submission.endpoint or "", submission.challenge_id, **common)
    if kind == "rctf":
        return RCTFChecker(submission.endpoint or "", submission.challenge_id, **common)
    if kind == "http":
        return HTTPChecker(
            submission.endpoint or "", method=ex.get("method", "POST"),
            flag_field=ex.get("flag_field", "flag"),
            success_status=ex.get("success_status", 200),
            success_contains=ex.get("success_contains"),
            extra_body=ex.get("extra_body"), headers=ex.get("headers"), **common,
        )
    return None
