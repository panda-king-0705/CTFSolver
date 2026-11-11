"""Command-line entry point. Feed it a target and/or files (or a challenge.json spec)
and it runs the whole pipeline, streaming the trace and printing the verified flag.

    ctfsolver demo
    ctfsolver solve --spec examples/toy_xor/challenge.json
    ctfsolver solve --name pwnme --target "nc host 1337" --file ./vuln --file ./libc.so.6
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from .config import Settings
from .memory.store import MemoryStore
from .models import Budget
from .orchestrator import Orchestrator, SolveReport
from .pipeline.intake import intake, intake_from_spec
from .trace import TraceEvent

_SYMBOL = {"start": "┌", "end": "└", "note": "·", "cmd": "$", "flag": "⚑", "error": "✗"}


def _printer(ev: TraceEvent) -> None:
    sym = _SYMBOL.get(ev.kind, "·")
    if ev.kind == "end":
        return  # keep the stream compact
    line = f"  {sym} {ev.block:<18} {ev.text}"
    print(line, file=sys.stderr)


def _run(challenge, settings: Settings, budget_usd: float, seed: bool,
         sandbox_factory=None) -> SolveReport:
    mem = MemoryStore(settings.db_path)
    if seed:
        try:
            from .memory.seed import seed_techniques

            n = seed_techniques(mem)
            print(f"[memory] seeded {n} techniques", file=sys.stderr)
        except Exception as exc:  # seed is optional
            print(f"[memory] seed skipped: {exc}", file=sys.stderr)
    orch = Orchestrator(memory=mem, settings=settings, sandbox_factory=sandbox_factory)
    from .trace import Trace

    trace = Trace(challenge.id)
    trace.on(_printer)
    return asyncio.run(orch.solve_challenge(challenge, Budget(usd=budget_usd), trace=trace))


def _save_writeup(rep: SolveReport, path: str | None) -> str | None:
    import re

    if not rep.writeup:
        return None
    if not path:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", rep.name).strip("-") or "challenge"
        path = os.path.join("writeups", f"{safe}-{rep.challenge_id[-6:]}.md")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(rep.writeup)
    return path


def _report(rep: SolveReport) -> int:
    o = rep.outcome
    print("\n" + "=" * 60)
    print(f"challenge : {rep.name}")
    print(f"status    : {o.status.value}")
    if o.flag:
        print(f"flag      : {o.flag.value}  (verified={o.flag.verified})")
    print(f"specialist: {o.specialist}")
    print(f"budget    : ${rep.ledger_snapshot['spent_usd']} · "
          f"{rep.ledger_snapshot['tool_calls']} tool calls")
    if o.notes:
        print(f"notes     : {o.notes}")
    print("=" * 60)
    return 0 if o.solved else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ctfsolver", description="Autonomous CTF solver")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("solve", help="solve a challenge")
    s.add_argument("--spec", help="path to a challenge.json")
    s.add_argument("--name", default="challenge")
    s.add_argument("--target", action="append", default=[], help="nc host port | url (repeatable)")
    s.add_argument("--file", action="append", default=[], help="handout file (repeatable)")
    s.add_argument("--flag-format", default=None)
    s.add_argument("--points", type=int, default=100)
    s.add_argument("--budget-usd", type=float, default=2.0)
    s.add_argument("--db", default=":memory:")
    s.add_argument("--no-seed", action="store_true")
    s.add_argument("--container", action="store_true",
                   help="run in the container sandbox (Docker) when a daemon is available")
    s.add_argument("--subscription", action="store_true",
                   help="route model calls through the local `claude` CLI (your Claude subscription)")
    s.add_argument("--writeup", metavar="PATH", default=None,
                   help="path to save the writeup (default: writeups/<name>.md)")
    s.add_argument("--no-writeup", action="store_true", help="don't save a writeup file")
    s.add_argument("--trace", metavar="PATH", default=None,
                   help="save the run's structured trace as JSON (for the console UI)")

    sub.add_parser("demo", help="run the offline toy challenge end to end")

    sv = sub.add_parser("serve", help="serve the web UI + JSON API")
    sv.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; use 0.0.0.0 to expose)")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--budget-usd", type=float, default=2.0, help="default budget per solve")
    sv.add_argument("--container", action="store_true",
                    help="run solves in the container sandbox when a daemon is available")
    sv.add_argument("--subscription", action="store_true",
                    help="route model calls through the local `claude` CLI")

    ev = sub.add_parser("eval", help="run the solver over a challenge set and measure it")
    ev.add_argument("path", help="a directory of challenge.json files, or a suite JSON")
    ev.add_argument("--budget-usd", type=float, default=2.0)
    ev.add_argument("--subscription", action="store_true",
                    help="route model calls through the local `claude` CLI")
    ev.add_argument("--json", metavar="PATH", default=None, help="save the full report as JSON")
    ev.add_argument("--md", metavar="PATH", default=None, help="save a markdown report")
    ev.add_argument("--sequential", action="store_true", help="run one at a time")

    args = p.parse_args(argv)
    settings = Settings()

    if args.cmd == "demo":
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(os.path.dirname(here))
        spec_path = os.path.join(root, "examples", "toy_xor", "challenge.json")
        if not os.path.exists(spec_path):
            print("toy challenge missing; run examples/toy_xor/make.py", file=sys.stderr)
            return 2
        with open(spec_path) as f:
            spec = json.load(f)
        spec["_base"] = os.path.dirname(spec_path)
        challenge = intake_from_spec(spec)
        rep = _run(challenge, settings, 2.0, seed=True)
        saved = _save_writeup(rep, None)
        if saved:
            print(f"[writeup] saved {saved}", file=sys.stderr)
        return _report(rep)

    if args.cmd == "serve":
        from .server import ServerConfig, serve

        cfg = ServerConfig(budget_usd=args.budget_usd, use_container=args.container,
                           subscription=args.subscription)
        httpd = serve(args.host, args.port, cfg)
        url = f"http://{args.host}:{args.port}"
        print(f"[serve] ctfsolver console on {url}  (Ctrl-C to stop)", file=sys.stderr)
        if args.container:
            print("[serve] solves use the container sandbox", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[serve] shutting down", file=sys.stderr)
            httpd.shutdown()
        return 0

    if args.cmd == "eval":
        import asyncio as _asyncio

        from .eval.harness import load_suite, render_markdown, run_eval

        if args.subscription:
            from .config import subscription_tier_models

            settings.tier_models = subscription_tier_models()
        specs = load_suite(args.path)
        print(f"[eval] running {len(specs)} challenges...", file=sys.stderr)
        report = _asyncio.run(run_eval(specs, settings=settings, budget_usd=args.budget_usd,
                                       concurrent=not args.sequential))
        md = render_markdown(report)
        print("\n" + md)
        if args.json:
            with open(args.json, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"[eval] wrote {args.json}", file=sys.stderr)
        if args.md:
            with open(args.md, "w") as f:
                f.write(md)
            print(f"[eval] wrote {args.md}", file=sys.stderr)
        return 0 if report.solved == report.total else 1

    # solve
    settings.db_path = args.db
    if args.spec:
        with open(args.spec) as f:
            spec = json.load(f)
        spec["_base"] = os.path.dirname(os.path.abspath(args.spec))
        challenge = intake_from_spec(spec)
    else:
        challenge = intake(
            args.name, targets=args.target, files=args.file,
            flag_format=args.flag_format, points=args.points,
        )
    if args.subscription:
        from .config import subscription_tier_models

        settings.tier_models = subscription_tier_models()
        print("[llm] routing tiers through the claude CLI (subscription)", file=sys.stderr)
    factory = None
    if args.container:
        from .sandbox.factory import auto_sandbox_factory

        factory = auto_sandbox_factory()
    rep = _run(challenge, settings, args.budget_usd, seed=not args.no_seed,
               sandbox_factory=factory)
    if not args.no_writeup:
        saved = _save_writeup(rep, args.writeup)
        if saved:
            print(f"[writeup] saved {saved}", file=sys.stderr)
    if args.trace:
        payload = rep.trace.to_payload(challenge=rep.name, summary={
            "status": rep.outcome.status.value,
            "flag": rep.outcome.flag.value if rep.outcome.flag else None,
            "verified": bool(rep.outcome.flag and rep.outcome.flag.verified),
            "specialist": rep.outcome.specialist, **rep.ledger_snapshot,
        })
        with open(args.trace, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"[trace] saved {args.trace}", file=sys.stderr)
    return _report(rep)


if __name__ == "__main__":
    raise SystemExit(main())
