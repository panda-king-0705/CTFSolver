# Handoff: CTF Solver Brain

Paste this into a new chat to continue working on the autonomous CTF solver. It is
self-contained. The code is the spec of record; this is the map.

- **Repo:** `panda-king-0705/CTFSolver` · **Working tree:** `/home/claude/ctfsolver` (tracks `origin/main`)
- **Run it:** `pip install -e ".[dev]" && pytest` (71 tests, fully offline) then
  `PYTHONPATH=src python -m ctfsolver.cli demo`
- **Architecture explorer (artifact):** https://claude.ai/artifact/3AcnJXnMAxvGhimUyf5EaD
- **Live console (artifact):** https://claude.ai/artifact/53YrQXzUhUX1feDg2nrvUn

## What it is

An AI system that solves CTF challenges (and supports **explicitly authorized** pentesting)
from **just an instance or a file**: a target (`nc host port` / URL), a file bundle (binary,
pcap, image, source, APK), or a container to spin up. Output: the flag.

It is built on AgentCo's **BrainEngine** design (the executive/manager cognition engine) with
one deliberate correction baked into the whole thing.

## The correction that shapes everything

The BrainEngine's own traced live runs found it **works poorly on tightly-coupled
engineering** — splitting one job across agents that can't run code caused guesswork,
verification sprawl and restore cascades. Exploitation is the most tightly-coupled work there
is. So:

> Keep the orchestration. Hand each challenge **whole** to one specialist with a real sandbox.
> The brain decides, budgets, routes, verifies and remembers; it **never fragments the exploit**.

This is non-negotiable and enforced by contract: routing is whole-challenge, and a
cross-category challenge is re-routed whole (`Outcome.reroute_to`), never split. Do not
reintroduce sub-task splitting of exploit work.

Three consequences:
1. **Orchestrate like the Brain** — triage, route, score confidence, budget, schedule many
   challenges by points-per-effort, escalate or stop. This is what the architecture is best at.
2. **Solve whole, in a real sandbox** — one specialist owns a challenge end to end, actually
   running code (`generate solver/exploit → run in sandbox → read flag`).
3. **The flag is the oracle** — no judge model; a flag matches a format and a checker accepts
   it, or it doesn't. The Brain's separate validator collapses to a regex + a submit.

## Pipeline (one pass per challenge)

Orchestrator oversees; six stages carry a challenge; Memory + Guardrails run underneath.

| Stage | Tier | What it does |
|---|---|---|
| **Intake** | economy | target / files / container → a normalized `Challenge` (+ category hint) |
| **Triage** | economy·standard | classify category + first-contact recon + recall matching techniques |
| **Route** | standard | hand the **whole** challenge to the one best-fit specialist |
| **Solve** | frontier·standard | the specialist iterates in its sandbox until a flag appears |
| **Verify** | economy | flag-format regex + scoreboard submission; empty-done guard |
| **Learn** | economy | bank the technique, log the episode, generate a reproducible writeup |

**Orchestrator** (frontier): runs many challenges concurrently by points-per-effort (value÷cost),
tracks budget/pressure, runs a bounded escalation ladder (retry → whole hand-off to a second
specialist → hint → human gate), detects out-of-distribution challenges.

**Specialists** — `pwn`, `web`, `rev`, `crypto`, `forensics`, `misc` — each a whole-challenge
owner. Crypto/misc solve classic challenges fully offline; every specialist has a live path
(`specialists/runner.py`: `run_script`, `run_provided`, `llm_write_and_run`) that generates and
runs a solver, container-gated where it needs isolation (running a provided binary) or egress
(web). Where it can't finish offline it lays out a concrete plan and blocks cleanly — it never
fabricates a flag.

## Guardrails (the core safety surface, not a footnote)

In `src/ctfsolver/guardrails/` + `sandbox/`:
- **Scope** (`scope.py`, `sandbox/egress.py`) — default-deny allow-list derived from the
  challenge's targets, enforced at the **network layer** (container egress firewall /
  iptables+nftables rules), not just the prompt. The solver cannot pivot off its given target.
- **Sandbox** (`sandbox/`) — `ContainerSandbox` runs a disposable, hardened container (caps
  dropped, read-only, tmpfs, resource caps; `SandboxLimits(cap_add=["SYS_PTRACE"])` for gdb).
  `LocalSandbox` is the offline CI substrate. `auto_sandbox_factory` picks container when a
  Docker daemon is up, else local.
- **Budget** (`budget.py`) — reservation ledger (USD / tool-calls / wall-clock); `can_afford`
  before, `charge` after; raises rather than overspending.
- **Audit** (`audit.py`) — append-only record of every command, egress, model call, gate decision.
- **Human gate** (`gate.py`) — default-deny for out-of-scope / destructive / sensitive actions.

Built for CTF and authorized testing only. See `docs/THREAT_MODEL.md`.

## What's real vs. what plugs in

**The control plane is complete and runs offline** on the standard library (71 tests): models,
trace, memory (sqlite3+FTS5), guardrails, the full pipeline, the orchestrator, crypto/misc
solvers, the eval harness, writeups, trace export.

Two things are interfaces with stubs, by design, so CI needs no network or heavy tooling:
- **LLM** (`llm/`) — a deterministic `StubClient` backs every tier. Real backends in
  `llm/providers.py`: Anthropic/OpenAI API (`CTFSOLVER_FRONTIER=anthropic:claude-opus-4-8` + the
  `providers` extra), and a **subscription provider** that routes calls through the local
  `claude` CLI so they run on a Claude subscription with **no API key** (`solve --subscription`,
  or `claude-cli:<model>`). Subscription calls don't spend the USD budget (call/time caps apply).
- **Sandbox** — the container path is real code; it runs where a Docker daemon exists. Build the
  image first: `docker build -f docker/toolbox.Dockerfile -t ctfsolver/toolbox:latest .`

## Scoreboard (closing the loop)

`pipeline/checkers.py` — CTFd, rCTF, and generic HTTP adapters. Configure per challenge; keep the
token in an env var, not the file:
```json
"submission": { "kind": "ctfd", "endpoint": "https://ctf.example",
                "challenge_id": 131, "extra": { "token_env": "CTFD_TOKEN" } }
```
Transport is injectable (tested offline). The token stays inside the checker and never reaches the
trace. With no `submission`, Verify falls back to the flag-format gate.

## Observability

- `solve --trace run.json` exports the full structured run trace (`Trace.to_payload()`); the live
  console artifact replays it (pipeline lights up block by block, ledger, flag, generated solver;
  drag-drop your own). Sample exports in `examples/traces/`.
- `solve` writes a reproducible markdown writeup to `writeups/<name>.md` (the generated solver is
  captured from the trace). `CTFSOLVER_WRITEUP_LLM=1` polishes the summary.
- `cli eval <dir|suite.json>` runs the solver over a set and reports solve rate / cost / time /
  per-category. Offline baseline over `examples/suite/`: **5/7** (crypto/misc/rev/forensics solve;
  pwn/web correctly miss pending the container image).

## File map (`src/ctfsolver/`)

```
models.py config.py trace.py            # vocabulary, settings/tiers, structured trace
cli.py orchestrator.py                  # entry point; the executive loop + scheduler + escalation
llm/      base.py stub.py providers.py  # tiered client; stub / API / subscription
memory/   store.py seed.py              # 4 stores (procedural/episodic/conceptual/working), FTS5
guardrails/ scope.py budget.py audit.py gate.py
sandbox/  base.py local.py container.py driver.py egress.py factory.py
pipeline/ intake.py triage.py route.py verify.py checkers.py writeup.py
specialists/ base.py registry.py runner.py pwn.py web.py rev.py crypto.py forensics.py misc.py
eval/     harness.py                    # run a set → metrics (solve rate, cost, time)
```
Docs: `README.md`, `docs/THREAT_MODEL.md`, `docs/SPECIALISTS.md` (write a new specialist),
`CONTRIBUTING.md`, `docker/`. Examples: `examples/{toy_xor,repeating_xor,suite,traces}/`.

## Conventions (keep these)

- **Control plane is stdlib-only and must stay offline-testable.** Heavy libs go behind optional
  extras + lazy imports; a missing SDK never breaks the control plane. `pytest` passes with only
  `[dev]` installed.
- **No fragmentation.** One specialist owns one challenge whole, in one sandbox. The only
  cross-specialist movement is a whole hand-off via `reroute_to`.
- **Everything network/filesystem-escaping goes through the sandbox**, so it's scope-checked,
  budget-charged and audited. Never around it.
- **Guardrail defaults stay safe:** scope default-deny, gate default-deny, audit append-only.
- Every change: code + offline test + green `pytest`; the behaviour shows in the trace.

## Honest status (2026-11-10)

Sprints 0–4 complete. ~5,000 LOC, 71 offline tests. The full loop is built, confined, measurable
and observable. **Works well offline today:** crypto/misc/rev/forensics on classic challenges, the
whole orchestration/guardrail/memory/verify/writeup/eval machinery. **Needs the operator's machine
to shine:** the container sandbox (daemon + toolbox image) so pwn/web and tool-backed solvers run
for real; and a live model wired into a tier (subscription is the no-key path) so a specialist
reasons through a hard challenge.

## Recommended next step

A **real run**: build the toolbox image, point it at a practice challenge with
`solve --spec chall.json --container --subscription --trace run.json`, replay the trace in the
console, and tune from what actually happened. After that: live paths hardened against real tooling,
remaining-specialist coverage, and a web console served from the trace stream.
