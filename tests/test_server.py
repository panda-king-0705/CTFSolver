"""The served web UI + JSON API. Exercised offline against a real ThreadingHTTPServer
on a loopback port: health, examples listing, the single-page UI, a non-streaming
solve, and a streaming (NDJSON) solve that ends in a verified flag -- all on the stub
provider + local sandbox, no network or Docker."""
from __future__ import annotations

import json
import threading
import urllib.request

from ctfsolver.server import ServerConfig, list_examples, run_solve, serve


def _free_server():
    httpd = serve("127.0.0.1", 0, ServerConfig(budget_usd=1.0))  # port 0 -> OS picks
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
        return r.status, r.read()


def _post(port, path, body, token="", host=None):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host:
        headers["Host"] = host
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read()


def test_list_examples_includes_bundled():
    ids = {e["id"] for e in list_examples()}
    assert {"toy_xor", "repeating_xor"} <= ids


def test_run_solve_toy_offline():
    result = run_solve({"example": "toy_xor"}, ServerConfig(budget_usd=1.0))
    assert result["summary"]["status"] == "solved"
    assert result["summary"]["verified"] is True
    assert result["summary"]["flag"].startswith("flag{")
    assert result["trace"]["events"]  # trace captured for the console


def test_build_challenge_rejects_unknown_example():
    import pytest
    with pytest.raises(ValueError):
        run_solve({"example": "../etc"}, ServerConfig())


def test_http_health_examples_and_index():
    httpd, port = _free_server()
    try:
        st, body = _get(port, "/api/health")
        assert st == 200 and json.loads(body)["status"] == "ok"

        st, body = _get(port, "/api/examples")
        assert st == 200
        assert any(e["id"] == "toy_xor" for e in json.loads(body)["examples"])

        st, body = _get(port, "/")
        assert st == 200 and b"ctfsolver console" in body

        st, _ = None, None
        try:
            _get(port, "/api/nope")
        except urllib.error.HTTPError as e:  # noqa: F821
            st = e.code
        assert st == 404
    finally:
        httpd.shutdown()


def test_http_solve_nonstreaming():
    httpd, port = _free_server()
    try:
        st, body = _post(port, "/api/solve", {"example": "toy_xor"}, token=httpd.auth_token)
        assert st == 200
        payload = json.loads(body)
        assert payload["summary"]["verified"] is True
        assert payload["writeup"]
    finally:
        httpd.shutdown()


def test_solve_requires_token():
    import urllib.error
    httpd, port = _free_server()
    try:
        code = None
        try:
            _post(port, "/api/solve", {"example": "toy_xor"})  # no token
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 401
    finally:
        httpd.shutdown()


def test_rejects_non_loopback_host():
    import urllib.error
    httpd, port = _free_server()
    try:
        code = None
        try:
            _post(port, "/api/solve", {"example": "toy_xor"},
                  token=httpd.auth_token, host="evil.example.com")
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403  # DNS-rebinding / LAN-exposure defence
    finally:
        httpd.shutdown()


def test_chat_reply_uses_configured_backend():
    from ctfsolver.server import ServerConfig, chat_reply
    r = chat_reply([{"role": "user", "content": "how do I approach a pwn challenge?"}],
                   ServerConfig())
    assert r.get("stub") is True                 # offline stub, honestly flagged
    assert r["model"].startswith("stub:")
    assert isinstance(r["reply"], str)
    assert chat_reply([], ServerConfig()).get("error")  # empty -> error, not a crash


def test_http_chat_endpoint():
    httpd, port = _free_server()
    try:
        st, body = _post(port, "/api/chat", {"messages": [{"role": "user", "content": "hi"}]}, token=httpd.auth_token)
        assert st == 200
        payload = json.loads(body)
        assert "reply" in payload and payload["stub"] is True
    finally:
        httpd.shutdown()


def test_http_solve_streaming_ndjson():
    httpd, port = _free_server()
    try:
        st, body = _post(port, "/api/solve?stream=1", {"example": "toy_xor"}, token=httpd.auth_token)
        assert st == 200
        msgs = [json.loads(line) for line in body.decode().splitlines() if line.strip()]
        kinds = [m["type"] for m in msgs]
        assert kinds[0] == "blocks"           # lanes announced first
        assert "event" in kinds               # live trace events streamed
        summary = [m for m in msgs if m["type"] == "summary"]
        assert summary and summary[0]["summary"]["verified"] is True
    finally:
        httpd.shutdown()
