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
    return {"block": ev.block, "kind": ev.kind, "text": ev.text, "data": ev.data}


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
# The console UI — single page, vanilla JS, no external assets (works offline).
# --------------------------------------------------------------------------- #
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ctfsolver console</title>
<style>
  :root{
    --bg:#0e1116; --panel:#161b22; --panel2:#1c2330; --line:#2a3340;
    --fg:#e6edf3; --muted:#8b98a9; --accent:#58a6ff; --ok:#3fb950; --bad:#f85149;
    --warn:#d29922; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;
         align-items:center;gap:12px}
  header h1{font-size:16px;margin:0;font-weight:600;letter-spacing:.2px}
  header .dot{width:9px;height:9px;border-radius:50%;background:var(--ok)}
  header .sub{color:var(--muted);font-size:12px}
  .wrap{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:16px;max-width:1200px;margin:0 auto}
  @media(max-width:820px){.wrap{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
  .panel h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
            margin:0 0 10px}
  label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
  select,input,textarea{width:100%;background:var(--panel2);color:var(--fg);
    border:1px solid var(--line);border-radius:7px;padding:8px;font-family:inherit;font-size:13px}
  textarea{font-family:var(--mono);min-height:120px;resize:vertical}
  .row{display:flex;gap:8px}
  .row>*{flex:1}
  button{background:var(--accent);color:#07111f;border:0;border-radius:7px;padding:10px 14px;
    font-weight:600;cursor:pointer;font-size:13px;width:100%;margin-top:12px}
  button:disabled{opacity:.5;cursor:default}
  .muted{color:var(--muted);font-size:12px}
  .pipeline{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
  .stage{flex:1;min-width:92px;text-align:center;padding:10px 6px;border-radius:8px;
    background:var(--panel2);border:1px solid var(--line);color:var(--muted);
    font-size:12px;transition:.15s;position:relative}
  .stage.active{border-color:var(--accent);color:var(--fg);box-shadow:0 0 0 1px var(--accent) inset}
  .stage.done{border-color:var(--ok);color:var(--fg)}
  .stage.err{border-color:var(--bad);color:var(--fg)}
  .result{display:none;margin-bottom:14px;padding:12px;border-radius:8px;background:var(--panel2);
    border:1px solid var(--line)}
  .result.show{display:block}
  .flag{font-family:var(--mono);font-size:15px;color:var(--ok);word-break:break-all}
  .flag.bad{color:var(--bad)}
  .badge{display:inline-block;font-size:11px;padding:2px 7px;border-radius:999px;
    border:1px solid var(--line);color:var(--muted);margin-left:6px}
  .badge.ok{color:var(--ok);border-color:var(--ok)}
  .log{font-family:var(--mono);font-size:12px;background:#0a0d12;border:1px solid var(--line);
    border-radius:8px;padding:10px;height:340px;overflow:auto}
  .log .ev{display:flex;gap:8px;padding:1px 0}
  .log .blk{color:var(--accent);min-width:150px}
  .log .flag-ev{color:var(--ok)}
  .log .cmd-ev{color:var(--warn)}
  .log .err-ev{color:var(--bad)}
  details{margin-top:12px}
  summary{cursor:pointer;color:var(--muted);font-size:12px}
  pre.writeup{white-space:pre-wrap;font-family:var(--mono);font-size:12px;background:#0a0d12;
    border:1px solid var(--line);border-radius:8px;padding:12px;max-height:380px;overflow:auto}
</style>
</head>
<body>
<header>
  <span class="dot"></span>
  <h1>ctfsolver</h1>
  <span class="sub">autonomous solver — live console</span>
</header>
<div class="wrap">
  <div class="panel">
    <h2>Challenge</h2>
    <label>Live instance <span class="muted">(nc host port, or a URL)</span></label>
    <input id="target" placeholder="nc chatelaine.cylabacademy.net 11517">
    <label>…or a bundled example</label>
    <select id="example"></select>
    <label><input type="checkbox" id="useRaw" style="width:auto;margin-right:6px">
      paste a raw spec instead</label>
    <textarea id="rawspec" style="display:none" placeholder='{"name":"demo","files":["..."],"flag_format":"flag\\{[^}]+\\}"}'></textarea>
    <div class="row">
      <div><label>Budget (USD)</label><input id="budget" type="number" value="2" step="0.5" min="0"></div>
    </div>
    <button id="go">Solve ▶</button>
    <p class="muted" id="hint" style="margin-top:12px"></p>
  </div>

  <div class="panel">
    <h2>Run</h2>
    <div class="pipeline" id="pipeline"></div>
    <div class="result" id="result">
      <div id="flag" class="flag"></div>
      <div class="muted" id="meta" style="margin-top:6px"></div>
      <details id="wdetails"><summary>writeup</summary><pre class="writeup" id="writeup"></pre></details>
    </div>
    <div class="log" id="log"></div>
  </div>
</div>
<script>
const $ = s => document.querySelector(s);
const BLOCK_LANE = b => { b = (b||"").split(":")[0]; return b.startsWith("solve") ? "solve" : b; };
let STAGES = [];

async function loadExamples(){
  const sel = $("#example");
  try{
    const r = await fetch("/api/examples"); const j = await r.json();
    (j.examples||[]).forEach(e=>{
      const o = document.createElement("option");
      o.value = e.id; o.textContent = `${e.name}${e.category?" ["+e.category+"]":""}`;
      o.title = e.description || ""; sel.appendChild(o);
    });
    updateHint();
  }catch(e){ $("#hint").textContent = "could not load examples"; }
}
function updateHint(){
  const sel = $("#example"); const opt = sel.options[sel.selectedIndex];
  $("#hint").textContent = opt ? (opt.title||"") : "";
}
$("#example").addEventListener("change", updateHint);
$("#useRaw").addEventListener("change", e=>{
  $("#rawspec").style.display = e.target.checked ? "block" : "none";
  $("#example").disabled = e.target.checked;
});

function renderPipeline(blocks){
  STAGES = blocks; const p = $("#pipeline"); p.innerHTML = "";
  blocks.forEach(b=>{
    const d = document.createElement("div");
    d.className = "stage"; d.id = "stage-"+b; d.textContent = b;
    p.appendChild(d);
  });
}
function markStage(lane, cls){
  const el = $("#stage-"+lane); if(!el) return;
  el.classList.remove("active"); el.classList.add(cls);
}
function logEvent(ev){
  const log = $("#log");
  const row = document.createElement("div"); row.className = "ev";
  const sym = {start:"┌",end:"└",note:"·",cmd:"$",flag:"⚑",error:"✗"}[ev.kind]||"·";
  let cls = ""; if(ev.kind==="flag")cls="flag-ev"; if(ev.kind==="cmd")cls="cmd-ev"; if(ev.kind==="error")cls="err-ev";
  row.innerHTML = `<span class="blk">${sym} ${ev.block}</span><span class="${cls}"></span>`;
  row.querySelector("span:last-child").textContent = ev.text||"";
  log.appendChild(row); log.scrollTop = log.scrollHeight;
}

async function solve(){
  $("#go").disabled = true; $("#result").classList.remove("show");
  $("#log").innerHTML = ""; renderPipeline([]);
  let body;
  const target = $("#target").value.trim();
  if($("#useRaw").checked){
    try{ body = {spec: JSON.parse($("#rawspec").value)}; }
    catch(e){ $("#hint").textContent = "raw spec is not valid JSON"; $("#go").disabled=false; return; }
  } else if(target){
    body = {name: "instance", targets: [target]};
  } else {
    body = {example: $("#example").value};
  }
  body.budget_usd = parseFloat($("#budget").value)||2;
  // budget is applied server-side via config; we still send it for forward-compat
  try{
    const res = await fetch("/api/solve?stream=1", {
      method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)
    });
    const reader = res.body.getReader(); const dec = new TextDecoder(); let buf = "";
    let activeLane = null;
    while(true){
      const {value, done} = await reader.read(); if(done) break;
      buf += dec.decode(value, {stream:true});
      let nl; while((nl = buf.indexOf("\n")) >= 0){
        const line = buf.slice(0, nl); buf = buf.slice(nl+1);
        if(!line.trim()) continue;
        const msg = JSON.parse(line);
        if(msg.type==="blocks"){ renderPipeline(msg.blocks); }
        else if(msg.type==="event"){
          logEvent(msg);
          const lane = BLOCK_LANE(msg.block);
          if(msg.kind==="start"){ if(activeLane && activeLane!==lane) markStage(activeLane,"done");
            activeLane = lane; markStage(lane,"active"); }
          if(msg.kind==="error") markStage(lane,"err");
        }
        else if(msg.type==="summary"){ if(activeLane) markStage(activeLane,"done"); showResult(msg); }
        else if(msg.type==="error"){ $("#hint").textContent = msg.error; }
      }
    }
  }catch(e){ $("#hint").textContent = "request failed: "+e; }
  $("#go").disabled = false;
}
function showResult(msg){
  const s = msg.summary||{}; const r = $("#result"); r.classList.add("show");
  const f = $("#flag");
  if(s.flag){ f.textContent = "⚑ "+s.flag; f.className = "flag"+(s.verified?"":" bad"); }
  else { f.textContent = "no flag"; f.className = "flag bad"; }
  const vb = s.verified ? '<span class="badge ok">verified</span>' : '<span class="badge">unverified</span>';
  $("#meta").innerHTML = `status ${s.status} · specialist ${s.specialist||"—"} `+vb+
    ` · $${s.spent_usd??0} · ${s.tool_calls??0} tool calls`+
    (s.notes?`<br><span class="muted">${s.notes}</span>`:"");
  if(msg.writeup){ $("#writeup").textContent = msg.writeup; $("#wdetails").style.display="block"; }
  else { $("#wdetails").style.display="none"; }
}
$("#go").addEventListener("click", solve);
loadExamples();
</script>
</body>
</html>
"""
