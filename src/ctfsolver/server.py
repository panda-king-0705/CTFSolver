"""Served web UI + JSON API for the solver.

Stdlib-only (``http.server`` + ``threading`` + ``queue``), so it honours the
control-plane rule: no dependencies, offline-testable. It exposes the same solve
pipeline the CLI runs and streams the trace live to a browser console.

Endpoints
---------
- ``GET  /``                  the single-page console UI
- ``GET  /api/health``        ``{"status": "ok"}``
- ``GET  /api/examples``      the bundled example challenges (whitelisted names)
- ``POST /api/solve``         run a solve; body is a challenge spec or
                              ``{"example": "<name>"}``. With ``?stream=1`` the
                              response is NDJSON: one ``{"type":"event",...}`` per
                              trace event, then a final ``{"type":"summary",...}``.
                              Without streaming it returns the whole run at once.

Safety: this is a code-execution surface (a solve runs tools in a sandbox). It
binds ``127.0.0.1`` by default; serve it wider only on a trusted network, in line
with "for CTF and authorized testing only".
"""
from __future__ import annotations

import asyncio
import json
import os
import queue
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from .config import Settings, subscription_tier_models
from .memory.store import MemoryStore
from .models import Budget
from .orchestrator import Orchestrator, SolveReport
from .pipeline.intake import intake, intake_from_spec
from .trace import Trace, TraceEvent

# The pipeline lanes the UI lights up, in order.
PIPELINE_BLOCKS = ["orchestrate", "triage", "route", "solve", "verify", "learn"]


def _repo_root() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(here))  # <root>/src/ctfsolver -> <root>


def _examples_dir() -> str:
    return os.path.join(_repo_root(), "examples")


def list_examples() -> list[dict]:
    """The bundled example challenges, each with its challenge.json metadata."""
    base = _examples_dir()
    out: list[dict] = []
    if not os.path.isdir(base):
        return out
    for name in sorted(os.listdir(base)):
        spec_path = os.path.join(base, name, "challenge.json")
        if not os.path.isfile(spec_path):
            continue
        try:
            with open(spec_path) as f:
                spec = json.load(f)
        except Exception:
            continue
        out.append({
            "id": name,
            "name": spec.get("name", name),
            "description": spec.get("description", ""),
            "category": spec.get("category", ""),
            "points": spec.get("points", 0),
        })
    return out


@dataclass
class ServerConfig:
    """Solve options applied to every run the server performs."""
    budget_usd: float = 2.0
    use_container: bool = False
    subscription: bool = False
    seed: bool = True


def _event_dict(ev: TraceEvent) -> dict:
    return {"block": ev.block, "kind": ev.kind, "text": ev.text,
            "data": ev.data, "ts": round(ev.ts, 3)}


def _build_challenge(payload: dict):
    """Turn a request body into a Challenge. Accepts a whitelisted example name, a
    full inline spec, or ad-hoc name/targets/files."""
    example = payload.get("example")
    if example:
        safe = os.path.basename(str(example))  # no traversal: basename only
        spec_path = os.path.join(_examples_dir(), safe, "challenge.json")
        if not os.path.isfile(spec_path):
            raise ValueError(f"unknown example: {example!r}")
        with open(spec_path) as f:
            spec = json.load(f)
        spec["_base"] = os.path.dirname(spec_path)
        return intake_from_spec(spec), spec.get("name", safe)
    if isinstance(payload.get("spec"), dict):
        spec = dict(payload["spec"])
        spec.setdefault("_base", os.getcwd())
        return intake_from_spec(spec), spec.get("name", "challenge")
    name = payload.get("name", "challenge")
    challenge = intake(
        name,
        targets=payload.get("targets", []) or [],
        files=payload.get("files", []) or [],
        flag_format=payload.get("flag_format"),
        points=int(payload.get("points", 100)),
    )
    return challenge, name


def run_solve(payload: dict, cfg: ServerConfig,
              on_event: Optional[Callable[[dict], None]] = None) -> dict:
    """Run one solve. If ``on_event`` is given it is called with each trace event as
    it happens. Returns a result dict (summary + writeup + full trace payload)."""
    challenge, name = _build_challenge(payload)

    settings = Settings()
    settings.db_path = ":memory:"
    if cfg.subscription:
        settings.tier_models = subscription_tier_models()

    mem = MemoryStore(settings.db_path)
    if cfg.seed:
        try:
            from .memory.seed import seed_techniques
            seed_techniques(mem)
        except Exception:
            pass

    factory = None
    if cfg.use_container:
        from .sandbox.factory import auto_sandbox_factory
        factory = auto_sandbox_factory()

    orch = Orchestrator(memory=mem, settings=settings, sandbox_factory=factory)
    trace = Trace(challenge.id)
    if on_event is not None:
        trace.on(lambda ev: on_event(_event_dict(ev)))

    try:
        budget_usd = float(payload.get("budget_usd", cfg.budget_usd))
    except (TypeError, ValueError):
        budget_usd = cfg.budget_usd
    rep: SolveReport = asyncio.run(
        orch.solve_challenge(challenge, Budget(usd=budget_usd), trace=trace)
    )
    o = rep.outcome
    summary = {
        "challenge": rep.name,
        "status": o.status.value,
        "flag": o.flag.value if o.flag else None,
        "verified": bool(o.flag and o.flag.verified),
        "specialist": o.specialist,
        "notes": o.notes,
        **rep.ledger_snapshot,
    }
    return {
        "summary": summary,
        "writeup": rep.writeup,
        "trace": rep.trace.to_payload(challenge=rep.name, summary=summary),
    }


CHAT_SYSTEM = (
    "You are the ctfsolver agent: a concise, practical CTF-solving assistant. You help with "
    "pwn, web, rev, crypto, forensics, misc, and live instances (SMB / printer / file shares, "
    "interactive nc services). You can also SOLVE a live instance directly: tell the user to "
    "paste `nc host port` or a URL and you'll run the pipeline and stream the trace. Keep "
    "answers short and actionable; give concrete commands. Never invent a flag."
)


def chat_reply(messages: list, cfg: ServerConfig) -> dict:
    """One conversational turn with the configured model. Honest about the backend: on the
    offline stub it says so (and returns the stub's canned text) rather than faking reasoning."""
    from .config import Tier
    from .llm.base import Message, get_client
    from .llm.stub import StubClient

    settings = Settings()
    if cfg.subscription:
        settings.tier_models = subscription_tier_models()
    model = settings.tier_models.get(Tier.FRONTIER) or "stub:frontier"
    try:
        client = get_client(model)
    except Exception:
        client = StubClient(str(model).split(":")[-1])

    msgs = [Message(m.get("role", "user"), m.get("content", ""))
            for m in (messages or [])[-16:] if m.get("content")]
    if not msgs:
        return {"error": "empty message"}
    try:
        resp = asyncio.run(client.complete(msgs, system=CHAT_SYSTEM, max_tokens=800))
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    model_name = str(getattr(resp, "model", "") or client.model)
    return {"reply": resp.text, "model": model_name, "stub": model_name.startswith("stub:")}


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #
def make_handler(cfg: ServerConfig):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ctfsolver/0.1"

        # -- helpers -------------------------------------------------------- #
        def _send_json(self, obj: Any, status: int = 200) -> None:
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            raw = self.rfile.read(length)
            try:
                return json.loads(raw or b"{}")
            except Exception:
                return {}

        def log_message(self, *a):  # quieter default logging
            return

        # -- routes --------------------------------------------------------- #
        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/" or path == "/index.html":
                body = INDEX_HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/health":
                self._send_json({"status": "ok"})
                return
            if path == "/api/examples":
                self._send_json({"examples": list_examples()})
                return
            self._send_json({"error": "not found"}, status=404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/chat":
                try:
                    reply = chat_reply(self._read_body().get("messages", []), cfg)
                except Exception as exc:
                    reply = {"error": f"{type(exc).__name__}: {exc}"}
                self._send_json(reply)
                return
            if parsed.path != "/api/solve":
                self._send_json({"error": "not found"}, status=404)
                return
            qs = parse_qs(parsed.query)
            stream = qs.get("stream", ["0"])[0] in ("1", "true", "yes")
            payload = self._read_body()

            if not stream:
                try:
                    result = run_solve(payload, cfg)
                except Exception as exc:
                    self._send_json({"error": f"{type(exc).__name__}: {exc}"}, status=400)
                    return
                self._send_json(result)
                return

            # streaming NDJSON: one JSON object per line, flushed as it arrives
            q: "queue.Queue[Optional[dict]]" = queue.Queue()

            def worker():
                try:
                    result = run_solve(payload, cfg, on_event=lambda e: q.put({"type": "event", **e}))
                    q.put({"type": "summary", "summary": result["summary"],
                           "writeup": result["writeup"]})
                except Exception as exc:
                    q.put({"type": "error", "error": f"{type(exc).__name__}: {exc}"})
                finally:
                    q.put(None)

            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            # tell the client which lanes exist up front
            self._write_line({"type": "blocks", "blocks": PIPELINE_BLOCKS})
            threading.Thread(target=worker, daemon=True).start()
            while True:
                item = q.get()
                if item is None:
                    break
                if not self._write_line(item):
                    break

        def _write_line(self, obj: dict) -> bool:
            try:
                self.wfile.write((json.dumps(obj) + "\n").encode())
                self.wfile.flush()
                return True
            except Exception:
                return False

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8000, cfg: Optional[ServerConfig] = None):
    """Build the HTTP server (caller runs ``.serve_forever()``). Returns the server."""
    cfg = cfg or ServerConfig()
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg))
    return httpd


# --------------------------------------------------------------------------- #
# The console UI -- a single-page "glass box" trace console in the AgentCo visual
# language (calm, dense ops console; hue reserved for data). Vanilla JS, no external
# assets, works offline. It streams a solve and shows the FULL trace: every stage span,
# every model call (honestly flagged when it's the offline stub), every sandbox command
# WITH its real output, and the generated solver source -- so you can watch the agent work.
# --------------------------------------------------------------------------- #
INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>ctfsolver console</title>
<script>try{var t=localStorage.getItem("ctfsolver.theme");if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t);}catch(e){}</script>
<style>
:root{
  color-scheme:light;
  --page:#f2f4f6; --surface:#fff; --surface-2:#f7f8fa; --surface-3:#edf0f3;
  --ink:#15191e; --ink-2:#48515c; --muted:#747d88; --line:#e0e4e9; --line-strong:#c9d0d8;
  --accent:#3550dc; --accent-ink:#fff; --accent-soft:#edf0ff; --accent-line:#c3ccfa;
  --good:#0ca30c; --good-ink:#0b6b1d; --warn:#e09a00; --warn-ink:#8a5a00; --warn-soft:#fff6e0;
  --danger:#d03b3b; --danger-ink:#b42323; --danger-soft:#fdeeee;
  --k-run:#2a78d6; --k-stage:#6250d6; --k-llm:#1baf7a; --k-tool:#eb6834;
  --k-memory:#008300; --k-system:#a0a7af; --k-flag:#0ca30c;
  --radius-panel:8px; --radius-ctl:6px; --radius-chip:4px;
  --font:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"DejaVu Sans Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  color-scheme:dark;
  --page:#0e1216; --surface:#151a20; --surface-2:#1a2027; --surface-3:#212830;
  --ink:#e5e8eb; --ink-2:#b2bac3; --muted:#87909a; --line:#262d36; --line-strong:#343e49;
  --accent:#8394ff; --accent-ink:#0e1216; --accent-soft:#1d2340; --accent-line:#3a4785;
  --good:#3ccf4a; --good-ink:#3ccf4a; --warn:#f0a92a; --warn-ink:#f3bd55; --warn-soft:#2d2412;
  --danger:#e66767; --danger-ink:#f08a8a; --danger-soft:#331b1d;
  --k-run:#3987e5; --k-stage:#9085e9; --k-llm:#199e70; --k-tool:#d95926;
  --k-memory:#2f9a2f; --k-system:#6d7680; --k-flag:#3ccf4a;
}}
:root[data-theme="dark"]{
  color-scheme:dark;
  --page:#0e1216; --surface:#151a20; --surface-2:#1a2027; --surface-3:#212830;
  --ink:#e5e8eb; --ink-2:#b2bac3; --muted:#87909a; --line:#262d36; --line-strong:#343e49;
  --accent:#8394ff; --accent-ink:#0e1216; --accent-soft:#1d2340; --accent-line:#3a4785;
  --good:#3ccf4a; --good-ink:#3ccf4a; --warn:#f0a92a; --warn-ink:#f3bd55; --warn-soft:#2d2412;
  --danger:#e66767; --danger-ink:#f08a8a; --danger-soft:#331b1d;
  --k-run:#3987e5; --k-stage:#9085e9; --k-llm:#199e70; --k-tool:#d95926;
  --k-memory:#2f9a2f; --k-system:#6d7680; --k-flag:#3ccf4a;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--page);color:var(--ink);font:13.5px/1.5 var(--font);-webkit-font-smoothing:antialiased}
.num,.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.muted{color:var(--muted)} .tiny{font-size:11px} .small{font-size:12px}
a{color:var(--accent)}
/* top bar */
.topbar{display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--surface);
  border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.brand{display:flex;align-items:center;gap:9px;font-weight:650}
.logo{width:22px;height:22px;border-radius:5px;display:block}
.brand .sub{color:var(--muted);font-weight:400;font-size:12px}
.spacer{flex:1}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;
  padding:3px 8px;border-radius:999px;border:1px solid var(--line-strong);color:var(--ink-2);background:var(--surface-2)}
.badge .dot{width:7px;height:7px;border-radius:50%;background:var(--muted)}
.badge.live .dot{background:var(--k-llm)} .badge.stub .dot{background:var(--warn)}
.iconbtn{background:var(--surface-2);border:1px solid var(--line);border-radius:var(--radius-ctl);
  color:var(--ink-2);cursor:pointer;padding:5px 9px;font-size:12px}
.iconbtn:hover{border-color:var(--line-strong)}
/* layout */
.wrap{max-width:1280px;margin:0 auto;padding:16px;display:grid;grid-template-columns:300px 1fr;gap:16px}
@media(max-width:900px){.wrap{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-panel)}
.panel>.head{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--line)}
.panel>.head h2{margin:0;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:650}
.panel>.body{padding:12px}
label{display:block;font-size:11.5px;color:var(--muted);margin:10px 0 4px}
label:first-child{margin-top:0}
input,select,textarea{width:100%;background:var(--surface-2);color:var(--ink);border:1px solid var(--line);
  border-radius:var(--radius-ctl);padding:7px 8px;font:inherit;font-size:13px}
input:focus,select:focus,textarea:focus{outline:2px solid var(--accent-soft);border-color:var(--accent-line)}
textarea{font-family:var(--mono);min-height:96px;resize:vertical;font-size:12px}
.check{display:flex;align-items:center;gap:7px;margin:10px 0 4px;color:var(--muted);font-size:12px}
.check input{width:auto}
.btn{background:var(--accent);color:var(--accent-ink);border:0;border-radius:var(--radius-ctl);
  padding:9px 14px;font-weight:650;cursor:pointer;width:100%;margin-top:12px;font-size:13px}
.btn:disabled{opacity:.55;cursor:default}
.hint{margin:10px 0 0;font-size:11.5px;color:var(--muted);min-height:1.2em}
/* kpis */
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:12px}
@media(max-width:700px){.kpis{grid-template-columns:repeat(3,1fr)}}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-ctl);padding:8px 10px}
.kpi .l{font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.kpi .v{font-size:16px;font-weight:650;margin-top:2px}
.kpi .v.mono{font-size:14px}
.kpi.flag .v{color:var(--good);font-family:var(--mono);font-size:13px;word-break:break-all}
.kpi.flag.bad .v{color:var(--danger)}
/* filters */
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.chip{display:inline-flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--line);
  border-radius:var(--radius-chip);padding:4px 8px;font-size:11.5px;color:var(--ink-2);cursor:pointer}
.chip[aria-pressed="true"]{background:var(--accent-soft);border-color:var(--accent-line);color:var(--ink)}
.sw{width:9px;height:9px;border-radius:2px;display:inline-block;flex:none}
/* glass box */
.glass{display:grid;grid-template-columns:1fr;gap:12px}
.glass.with-panel{grid-template-columns:1fr 340px}
@media(max-width:1050px){.glass.with-panel{grid-template-columns:1fr}}
/* waterfall */
.wf{font-size:12.5px}
.wf-head{display:flex;align-items:center;height:22px;border-bottom:1px solid var(--line);color:var(--muted)}
.wf-name{width:46%;min-width:200px;padding-left:8px}
.wf-axis{flex:1;position:relative;height:100%}
.wf-axis span{position:absolute;transform:translateX(-50%);font-size:10px;top:5px;color:var(--muted)}
.wf-row{display:flex;align-items:center;min-height:26px;border-bottom:1px solid var(--line);cursor:pointer}
.wf-row:hover{background:var(--surface-2)}
.wf-row.sel{background:var(--accent-soft)}
.wf-row.err{background:var(--danger-soft)}
.wf-name{display:flex;align-items:center;gap:7px;overflow:hidden}
.wf-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.wf-label.mono{font-family:var(--mono);font-size:11.5px}
.wf-meta{margin-left:auto;padding-right:8px;color:var(--muted);font-size:10.5px;white-space:nowrap}
.wf-bars{flex:1;position:relative;height:18px}
.wf-bar{position:absolute;top:4px;height:10px;border-radius:3px;min-width:3px;opacity:.9}
.wf-bar.running{background:repeating-linear-gradient(90deg,currentColor 0 6px,transparent 6px 10px);opacity:.6}
.wf-dur{position:absolute;top:3px;font-size:9.5px;color:var(--muted)}
.k-run{background:var(--k-run);color:var(--k-run)} .k-stage{background:var(--k-stage);color:var(--k-stage)}
.k-llm{background:var(--k-llm);color:var(--k-llm)} .k-tool{background:var(--k-tool);color:var(--k-tool)}
.k-note{background:var(--k-system);color:var(--k-system)} .k-flag{background:var(--k-flag);color:var(--k-flag)}
.k-error{background:var(--danger);color:var(--danger)} .k-script{background:var(--k-tool);color:var(--k-tool)}
/* detail */
.detail{align-self:start}
.detail .body{padding:12px;max-height:72vh;overflow:auto}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12px}
.kv dt{color:var(--muted)} .kv dd{margin:0;text-align:right;font-family:var(--mono);font-size:11.5px;word-break:break-word}
.sec{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:14px 0 6px}
pre.io{white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:11.5px;background:var(--surface-2);
  border:1px solid var(--line);border-radius:var(--radius-ctl);padding:9px;margin:0;max-height:300px;overflow:auto}
.callout{display:flex;gap:8px;padding:9px;border-radius:var(--radius-ctl);font-size:12px;margin-bottom:10px}
.callout.good{background:var(--good-ink);color:#fff}
.callout.danger{background:var(--danger-soft);color:var(--danger-ink);border:1px solid var(--danger)}
.pill{display:inline-block;font-size:10px;font-weight:650;padding:1px 6px;border-radius:999px;border:1px solid var(--line-strong);color:var(--ink-2)}
.pill.stub{background:var(--warn-soft);color:var(--warn-ink);border-color:var(--warn)}
.pill.real{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)}
.empty{padding:28px 12px;text-align:center;color:var(--muted);font-size:12.5px}
.result-flag{font-family:var(--mono);font-size:14px;word-break:break-all}
details>summary{cursor:pointer;color:var(--muted);font-size:12px;margin-top:10px}
pre.writeup{white-space:pre-wrap;font-family:var(--mono);font-size:11.5px;background:var(--surface-2);
  border:1px solid var(--line);border-radius:var(--radius-ctl);padding:10px;max-height:360px;overflow:auto;margin-top:8px}
/* chat */
.chatpanel{display:flex;flex-direction:column}
.chatpanel .head .mini{font-size:11px;color:var(--muted)}
.chatpanel .head .mini input{width:52px;padding:2px 5px;font-size:11px;display:inline-block}
.chat{flex:1;overflow:auto;padding:12px;display:flex;flex-direction:column;gap:9px;min-height:260px;max-height:58vh}
.msg{display:flex} .msg.user{justify-content:flex-end}
.bubble{max-width:88%;padding:8px 10px;border-radius:10px;font-size:12.5px;line-height:1.45;white-space:pre-wrap;word-break:break-word}
.msg.agent .bubble{background:var(--surface-2);border:1px solid var(--line);border-bottom-left-radius:3px}
.msg.user .bubble{background:var(--accent);color:var(--accent-ink);border-bottom-right-radius:3px}
.bubble code{font-family:var(--mono);font-size:11.5px;background:rgba(127,127,127,.18);padding:1px 4px;border-radius:3px}
.bubble .flagtext{font-family:var(--mono);color:var(--good)}
.typing{display:inline-block;color:var(--muted);animation:blink 1s steps(2) infinite}
@keyframes blink{50%{opacity:.3}}
.composer{display:flex;gap:8px;padding:10px 12px;border-top:1px solid var(--line)}
.composer textarea{min-height:0;height:auto;flex:1;resize:none}
.composer .btn{width:auto;margin-top:0;align-self:stretch;padding:0 16px}
</style>
</head>
<body>
<header class="topbar">
  <span class="brand">
    <svg class="logo" viewBox="0 0 32 32" aria-hidden="true"><rect x="3" y="5" width="26" height="6" rx="1.5" fill="#2a78d6"/><rect x="3" y="13" width="26" height="6" rx="1.5" fill="#6250d6"/><rect x="3" y="21" width="26" height="6" rx="1.5" fill="#1baf7a"/></svg>
    ctfsolver <span class="sub">glass box — watch the agent solve</span>
  </span>
  <span class="spacer"></span>
  <span class="badge" id="backend"><span class="dot"></span><span id="backend-t">model: —</span></span>
  <button class="iconbtn" id="theme" title="Toggle theme">◐ theme</button>
</header>
<div class="wrap">
  <!-- agent chat -->
  <section class="panel chatpanel" style="align-self:start">
    <div class="head"><h2>Agent</h2><span class="spacer"></span>
      <span class="mini">budget $<input id="budget" type="number" value="2" step="0.5" min="0"></span></div>
    <div class="chat" id="chat">
      <div class="msg agent"><div class="bubble">I'm the CTF solver. Paste a live instance (<code>nc host port</code> or a URL) and I'll solve it — the full trace streams on the right. Or ask me anything about a challenge.</div></div>
    </div>
    <div class="composer">
      <textarea id="msg" rows="2" placeholder="Message the agent, or paste an instance to solve…"></textarea>
      <button class="btn" id="send">Send</button>
    </div>
    <p class="hint" id="hint"></p>
  </section>
  <!-- run -->
  <section>
    <div class="kpis" id="kpis"></div>
    <div class="chips" id="filters"></div>
    <div class="glass" id="glass">
      <div class="panel">
        <div class="head"><h2 id="wf-title">Trace</h2></div>
        <div class="body" style="padding:0">
          <div class="wf" id="wf"><div class="empty">Pick a challenge and hit Solve — the agent's full trace streams here live.</div></div>
        </div>
      </div>
      <aside class="panel detail" id="detail" style="display:none">
        <div class="head"><h2 id="detail-title">Detail</h2><span class="spacer"></span><button class="iconbtn" id="detail-close">✕</button></div>
        <div class="body" id="detail-body"></div>
      </aside>
    </div>
    <div id="result"></div>
  </section>
</div>
<script>
const $=s=>document.querySelector(s), el=(t,c)=>{const e=document.createElement(t);if(c)e.className=c;return e;};
let EVENTS=[], SELECTED=null, SUMMARY=null, RUNNING=false, NOW=0;

// ---- kind mapping (CTFSolver trace -> AgentCo span kinds) ----
const STAGE_BLOCKS=new Set(["triage","route","solve","verify","learn","escalate","intake"]);
function laneKind(ev){
  if(ev.kind==="llm")return"llm";
  if(ev.kind==="cmd"||ev.kind==="script")return"tool";
  if(ev.kind==="flag")return"flag";
  if(ev.kind==="error")return"error";
  if(ev.kind==="note")return"note";
  // span (start/end): orchestrate=run, pipeline stages=stage
  return ev.block==="orchestrate"?"run":"stage";
}
const KIND_LABEL={run:"orchestrate",stage:"stage",llm:"model call",tool:"sandbox",note:"note",flag:"flag",error:"error",script:"solver"};
const ALL_KINDS=["run","stage","llm","tool","note","flag","error"];
let KIND_FILTER=new Set();

// ---- build a span tree from the flat event stream ----
function buildTree(events){
  const roots=[], stack=[];
  for(const ev of events){
    const top=stack[stack.length-1];
    if(ev.kind==="start"){
      const n={kind:"span",lane:laneKind(ev),block:ev.block,name:ev.text||ev.block,t:ev.ts,tEnd:null,ev,children:[]};
      (top?top.children:roots).push(n); stack.push(n);
    } else if(ev.kind==="end"){
      const n=stack.pop(); if(n){n.tEnd=ev.ts; n.seconds=(ev.data&&ev.data.seconds)||null;}
    } else {
      const n={kind:"leaf",lane:laneKind(ev),ekind:ev.kind,block:ev.block,name:ev.text,t:ev.ts,data:ev.data||{},ev,children:[]};
      (top?top.children:roots).push(n);
    }
  }
  return roots;
}
function flatten(nodes,depth,out){for(const n of nodes){n.depth=depth;out.push(n);if(n.children&&n.children.length)flatten(n.children,depth+1,out);}return out;}

function timeBounds(events){
  if(!events.length)return[0,1];
  let t0=Infinity,t1=-Infinity;
  for(const e of events){t0=Math.min(t0,e.ts);t1=Math.max(t1,e.ts);}
  if(RUNNING)t1=Math.max(t1,NOW);
  return[t0,Math.max(t1,t0+0.001)];
}
function fmtDur(s){if(s==null)return"";if(s<1)return Math.round(s*1000)+"ms";if(s<60)return s.toFixed(s<10?2:1)+"s";return Math.floor(s/60)+"m"+Math.round(s%60)+"s";}

// ---- render waterfall ----
function renderWF(){
  const wf=$("#wf"); wf.innerHTML="";
  const filtered = KIND_FILTER.size? EVENTS.filter(e=>{const k=e.kind==="start"||e.kind==="end"?laneKind(e):laneKind(e);return KIND_FILTER.has(k)|| (e.kind==="end");}) : EVENTS;
  const roots=buildTree(EVENTS);
  const rows=flatten(roots,0,[]);
  const shown = KIND_FILTER.size? rows.filter(n=>KIND_FILTER.has(n.lane)) : rows;
  $("#wf-title").textContent="Trace ("+shown.length+" span"+(shown.length===1?"":"s")+")";
  if(!rows.length){wf.innerHTML='<div class="empty">Pick a challenge and hit Solve — the agent’s full trace streams here live.</div>';return;}
  const[t0,t1]=timeBounds(EVENTS), total=t1-t0;
  // axis
  const head=el("div","wf-head"); const nm=el("div","wf-name muted small");nm.textContent="Span";head.appendChild(nm);
  const ax=el("div","wf-axis");[0,.25,.5,.75,1].forEach(f=>{const s=el("span","num");s.style.left=(f*100)+"%";s.textContent=fmtDur(total*f);ax.appendChild(s);});
  head.appendChild(ax); wf.appendChild(head);
  for(const n of shown){
    const row=el("div","wf-row"+(SELECTED===n.ev?" sel":"")+(n.ekind==="error"?" err":""));
    row.onclick=()=>{SELECTED=n.ev; renderWF(); renderDetail(n);};
    const name=el("div","wf-name"); name.style.paddingLeft=(8+n.depth*14)+"px";
    const sw=el("span","sw"); sw.style.background="var(--k-"+(n.lane==="tool"?"tool":n.lane==="llm"?"llm":n.lane==="run"?"run":n.lane==="flag"?"flag":n.lane==="error"?"error":n.lane==="note"?"system":"stage")+")";
    name.appendChild(sw);
    const lab=el("span","wf-label"+(n.kind==="leaf"&&(n.ekind==="cmd"||n.ekind==="llm")?" mono":""));
    lab.textContent=(n.kind==="span"?n.name:(n.ekind==="flag"?"⚑ "+n.name:n.ekind==="cmd"?"$ "+n.name:n.name))||("("+n.block+")");
    lab.title=lab.textContent; name.appendChild(lab);
    const meta=el("span","wf-meta");
    if(n.kind==="span")meta.textContent=fmtDur(n.seconds!=null?n.seconds:(n.tEnd?n.tEnd-n.t:(RUNNING?NOW-n.t:null)));
    else if(n.ekind==="llm"&&n.data)meta.textContent=(n.data.stub?"stub":"")+" "+(n.data.latency_ms!=null?n.data.latency_ms+"ms":"");
    else if(n.ekind==="cmd"&&n.data&&n.data.rc!=null)meta.textContent="rc="+n.data.rc;
    name.appendChild(meta);
    const bars=el("div","wf-bars");
    const start=n.t, end=n.kind==="span"?(n.tEnd||t1):n.t;
    const left=((start-t0)/total)*100;
    let width=((end-start)/total)*100; if(n.kind==="leaf")width=Math.max(width,0.6); width=Math.max(width,0.4);
    const bar=el("span","wf-bar k-"+(n.lane==="note"?"note":n.lane)+(n.kind==="span"&&!n.tEnd&&RUNNING?" running":""));
    bar.style.left=left+"%"; bar.style.width=Math.min(width,100-left)+"%";
    bars.appendChild(bar);
    name.style.width="46%"; name.style.minWidth="200px"; name.style.flex="none";
    row.appendChild(name); row.appendChild(bars); wf.appendChild(row);
  }
}

// ---- detail panel ----
function kv(rows){const d=el("dl","kv");for(const[k,v]of rows){if(v==null||v==="")continue;const dt=el("dt");dt.textContent=k;const dd=el("dd");if(v instanceof Node)dd.appendChild(v);else dd.textContent=v;d.appendChild(dt);d.appendChild(dd);}return d;}
function pre(text){const p=el("pre","io");p.textContent=text||"—";return p;}
function sec(t){const h=el("div","sec");h.textContent=t;return h;}
function renderDetail(n){
  const d=$("#detail"), b=$("#detail-body"); d.style.display=""; $("#glass").classList.add("with-panel");
  b.innerHTML=""; const data=n.data||{};
  if(n.kind==="span"){
    $("#detail-title").textContent="Span · "+n.block;
    b.appendChild(kv([["Block",n.block],["Name",n.name],["Status",n.tEnd?"done":"running"],["Duration",fmtDur(n.seconds!=null?n.seconds:(n.tEnd?n.tEnd-n.t:null))]]));
    return;
  }
  if(n.ekind==="llm"){
    $("#detail-title").textContent="Model call";
    const pill=el("span","pill "+(data.stub?"stub":"real"));pill.textContent=data.stub?"stub (offline)":"real model";
    b.appendChild(kv([["Model",data.model||n.block],["Backend",pill],["Stage",data.stage||"—"],["Latency",data.latency_ms!=null?data.latency_ms+" ms":"—"],["Tokens",(data.tokens_in||0)+" in / "+(data.tokens_out||0)+" out"],["Cost",data.cost!=null?"$"+data.cost:"—"]]));
    b.appendChild(sec("Reply preview")); b.appendChild(pre(data.preview));
    return;
  }
  if(n.ekind==="cmd"){
    $("#detail-title").textContent="Sandbox command";
    b.appendChild(kv([["Command",n.name],["Exit code",data.rc],["Duration",fmtDur(data.seconds)],["Flag found",data.flag?"yes":"no"]]));
    b.appendChild(sec("stdout")); b.appendChild(pre(data.stdout));
    if(data.stderr){b.appendChild(sec("stderr")); b.appendChild(pre(data.stderr));}
    return;
  }
  if(n.ekind==="script"){
    $("#detail-title").textContent="Generated solver";
    b.appendChild(kv([["File",n.name],["Language",data.lang||"text"]]));
    b.appendChild(sec("source")); b.appendChild(pre(data.source));
    return;
  }
  if(n.ekind==="flag"){
    $("#detail-title").textContent="Flag";
    const c=el("div","callout good");c.textContent="⚑ "+n.name;b.appendChild(c);
    b.appendChild(kv([["Block",n.block]]));return;
  }
  if(n.ekind==="error"){
    $("#detail-title").textContent="Error";
    const c=el("div","callout danger");c.textContent=n.name;b.appendChild(c);return;
  }
  $("#detail-title").textContent="Note";
  const p=el("div");p.style.fontSize="12.5px";p.textContent=n.name;b.appendChild(p);
  b.appendChild(kv([["Block",n.block]]));
}
$("#detail-close").onclick=()=>{$("#detail").style.display="none";$("#glass").classList.remove("with-panel");SELECTED=null;renderWF();};

// ---- kpis + backend + filters ----
function renderKPIs(){
  const[t0,t1]=timeBounds(EVENTS);
  const llm=EVENTS.filter(e=>e.kind==="llm"), cmd=EVENTS.filter(e=>e.kind==="cmd");
  const status=SUMMARY?SUMMARY.status:(RUNNING?"running":"idle");
  const flag=SUMMARY&&SUMMARY.flag?SUMMARY.flag:null;
  const cards=[["Status",status,""],["Duration",fmtDur(EVENTS.length?t1-t0:0),"mono"],
    ["Events",String(EVENTS.filter(e=>e.kind!=="end").length),"mono"],["Model calls",String(llm.length),"mono"],
    ["Commands",String(cmd.length),"mono"],["Flag",flag||"—","flag"+(flag&&SUMMARY.verified?"":" bad")]];
  const k=$("#kpis");k.innerHTML="";
  for(const[l,v,cls]of cards){const c=el("div","kpi"+(cls==="flag"||cls==="flag bad"?" "+cls:""));
    const L=el("div","l");L.textContent=l;const V=el("div","v"+(cls==="mono"?" mono":""));V.textContent=v;c.appendChild(L);c.appendChild(V);k.appendChild(c);}
  // backend badge from llm events
  const real=llm.find(e=>e.data&&!e.data.stub), anyStub=llm.find(e=>e.data&&e.data.stub);
  const bb=$("#backend"), bt=$("#backend-t");
  if(real){bb.className="badge live";bt.textContent="model: "+real.data.model;}
  else if(anyStub){bb.className="badge stub";bt.textContent="model: stub (offline)";}
  else{bb.className="badge";bt.textContent="model: —";}
}
function renderFilters(){
  const f=$("#filters");f.innerHTML="";
  for(const k of ALL_KINDS){
    const c=el("button","chip");c.setAttribute("aria-pressed",KIND_FILTER.has(k));
    const sw=el("span","sw");sw.style.background="var(--k-"+(k==="note"?"system":k)+")";
    c.appendChild(sw);c.appendChild(document.createTextNode(KIND_LABEL[k]));
    c.onclick=()=>{if(KIND_FILTER.has(k))KIND_FILTER.delete(k);else KIND_FILTER.add(k);renderFilters();renderWF();};
    f.appendChild(c);
  }
}

// ---- result ----
function renderResult(msg){
  SUMMARY=msg.summary||{}; const r=$("#result");r.innerHTML="";
  const p=el("div","panel");p.style.marginTop="12px";
  const h=el("div","head");const t=el("h2");t.textContent="Result";h.appendChild(t);p.appendChild(h);
  const bd=el("div","body");
  const s=SUMMARY;
  const fl=el("div","result-flag");fl.style.color=s.flag&&s.verified?"var(--good)":"var(--danger)";
  fl.textContent=s.flag?("⚑ "+s.flag+(s.verified?"  ✓ verified":"  (unverified)")):"no flag recovered";
  bd.appendChild(fl);
  const meta=el("div","muted small");meta.style.marginTop="6px";
  meta.textContent="status "+s.status+" · specialist "+(s.specialist||"—")+" · $"+(s.spent_usd!=null?s.spent_usd:0)+" · "+(s.tool_calls!=null?s.tool_calls:0)+" tool calls"+(s.notes?" · "+s.notes:"");
  bd.appendChild(meta);
  if(msg.writeup){const dt=el("details");const sm=el("summary");sm.textContent="writeup";dt.appendChild(sm);const pr=el("pre","writeup");pr.textContent=msg.writeup;dt.appendChild(pr);bd.appendChild(dt);}
  p.appendChild(bd);r.appendChild(p);
}

// ---- theme ----
$("#theme").onclick=()=>{const cur=document.documentElement.getAttribute("data-theme");const next=cur==="dark"?"light":(cur==="light"?"dark":(matchMedia("(prefers-color-scheme: dark)").matches?"light":"dark"));document.documentElement.setAttribute("data-theme",next);try{localStorage.setItem("ctfsolver.theme",next);}catch(e){}};

// ---- run a solve (streams the trace into the waterfall); calls onDone(summary,writeup,err) ----
let clock=null;
async function runSolve(body,onDone){
  if(RUNNING)return;
  EVENTS=[];SELECTED=null;SUMMARY=null;$("#result").innerHTML="";$("#detail").style.display="none";$("#glass").classList.remove("with-panel");
  body.budget_usd=parseFloat($("#budget").value)||2;
  RUNNING=true;NOW=0;let T0=performance.now();
  clock=setInterval(()=>{if(EVENTS.length){NOW=EVENTS[0].ts+(performance.now()-T0)/1000;renderWF();renderKPIs();}},250);
  try{
    const res=await fetch("/api/solve?stream=1",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const rd=res.body.getReader(),dec=new TextDecoder();let buf="";
    while(true){const{value,done}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});
      let nl;while((nl=buf.indexOf("\n"))>=0){const line=buf.slice(0,nl);buf=buf.slice(nl+1);if(!line.trim())continue;
        const m=JSON.parse(line);
        if(m.type==="event"){EVENTS.push(m);if(EVENTS.length===1)T0=performance.now();NOW=Math.max(NOW,m.ts);renderWF();renderKPIs();}
        else if(m.type==="summary"){renderResult(m);if(onDone)onDone(m.summary,m.writeup,null);}
        else if(m.type==="error"){if(onDone)onDone(null,null,m.error);}
      }
    }
  }catch(e){if(onDone)onDone(null,null,String(e));}
  RUNNING=false;clearInterval(clock);renderWF();renderKPIs();
}

// ---- chat with the agent ----
const TARGET_RE=/(nc\s+[a-z0-9.\-]+\s+\d{1,5}|https?:\/\/\S+|[a-z0-9][a-z0-9.\-]*\s*:\s*\d{2,5})/i;
function detectTarget(s){const m=s.match(TARGET_RE);return m?m[0].replace(/\s*:\s*/,":").trim():null;}
const CHAT=[];
function esc(s){return(s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function addMsg(role,html){const c=$("#chat");const w=el("div","msg "+role);const b=el("div","bubble");if(html instanceof Node)b.appendChild(html);else b.innerHTML=html;w.appendChild(b);c.appendChild(w);c.scrollTop=c.scrollHeight;return b;}
function setBackend(stub,model){const bb=$("#backend"),bt=$("#backend-t");if(stub){bb.className="badge stub";bt.textContent="model: stub (offline)";}else if(model){bb.className="badge live";bt.textContent="model: "+model;}}

async function send(){
  const ta=$("#msg");const text=ta.value.trim();if(!text||RUNNING)return;
  ta.value="";addMsg("user",esc(text));
  const target=detectTarget(text);
  const solveIntent=target&&(/\b(solve|flag|pwn|crack|get|grab|retrieve|run|try|exploit|enumerate)\b/i.test(text)||/^(nc\s|https?:\/\/)/i.test(text));
  if(solveIntent){
    const b=addMsg("agent","Solving <code>"+esc(target)+"</code> — streaming the trace →");
    await runSolve({name:"instance",targets:[target]},(summary,writeup,err)=>{
      if(err){b.innerHTML="⚠ "+esc(err);return;}
      if(summary&&summary.flag){b.innerHTML="⚑ <b class='flagtext'>"+esc(summary.flag)+"</b>"+(summary.verified?" ✓ verified":" (unverified)")+" — via "+esc(summary.specialist||"solver")+". Full trace on the right →";}
      else{b.innerHTML="No flag recovered"+((summary&&summary.notes)?": "+esc(summary.notes):"")+". The trace shows exactly what was tried →";}
    });
    return;
  }
  CHAT.push({role:"user",content:text});
  const b=addMsg("agent","<span class='typing'>…</span>");
  try{
    const r=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({messages:CHAT})});
    const j=await r.json();
    if(j.error){b.innerHTML="⚠ "+esc(j.error);return;}
    b.textContent=j.reply||"(no reply)";
    CHAT.push({role:"assistant",content:j.reply||""});
    setBackend(j.stub,j.model);
  }catch(e){b.innerHTML="⚠ "+esc(e);}
}
$("#send").addEventListener("click",send);
$("#msg").addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send();}});

renderFilters();renderKPIs();
// deep link: /?target=nc+host+port auto-starts a solve from chat
const q=new URLSearchParams(location.search);
if(q.get("target")){$("#msg").value="solve "+q.get("target");send();}
</script>
</body>
</html>
'''
