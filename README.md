# ctfsolver

An autonomous CTF solver built on the **BrainEngine** design. You hand it a challenge —
a target (`nc host port` / URL), a file, or a container to run — and it drives the
challenge to a verified flag.

The guiding correction, taken straight from the BrainEngine's traced live runs: the
brain is strong at orchestration and **weak at splitting tightly-coupled work across
agents that cannot run code**. Exploitation is maximally coupled, so the orchestrator
decides, budgets, routes, verifies and remembers — but every challenge is handed
**whole** to a single specialist with a real sandbox. The orchestrator never fragments
the exploit.

> **For CTF and explicitly authorized testing only.** Scope confinement is a first-class,
> tested guardrail — the solver cannot touch anything but the target it was given. Read
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before running it against anything.

## Quickstart

```sh
# no dependencies needed for the control plane — it runs on the stdlib
python -m pytest                      # 28 tests, fully offline
PYTHONPATH=src python -m ctfsolver.cli demo
```

The demo solves a self-contained toy challenge (a flag that's single-byte XOR'd then
base64'd) end to end and prints the walked pipeline:

```
┌ orchestrate        toy-xor
┌ triage             toy-xor
· triage             recalled: XOR over base64 decode-first; ...
· triage             category=crypto subtype=encoding score=1.0
┌ route              category=crypto fit=0.89 -> crypto-specialist (whole-challenge hand-off)
┌ solve:crypto-specialist escalation=0
┌ verify             ⚑ flag{x0r_4nd_base64_are_not_crypto}
┌ learn              banked technique; verified flag ...
status : solved   flag : flag{x0r_4nd_base64_are_not_crypto}  (verified=True)
```

Solve your own:

```sh
PYTHONPATH=src python -m ctfsolver.cli solve \
  --name pwnme --target "nc host 1337" --file ./vuln --file ./libc.so.6
# or from a spec
PYTHONPATH=src python -m ctfsolver.cli solve --spec challenge.json
```

<!-- PROGRESS: Sprints 0-3 complete; Sprint 4 eval harness done. 70 offline tests pass.
Delivered: full pipeline, 4-store memory, guardrails (scope/budget/audit/gate), container
sandbox with network-layer egress, CTFd/rCTF checkers, subscription (claude CLI) provider,
toolbox image, live execution for all specialists, writeups, eval harness. Remaining: a
trace/console UI; real-tool live runs once a toolbox image is built. -->

## Run on your Claude subscription (no API key)

Instead of setting up API billing, route the model calls through the local `claude` CLI
(Claude Code), which uses your logged-in Claude subscription:

```sh
npm i -g @anthropic-ai/claude-code && claude login   # one-time, if not already
PYTHONPATH=src python -m ctfsolver.cli solve --spec challenge.json --subscription --budget-usd 20
```

`--subscription` points every tier at `claude-cli:<model>` (frontier→opus, standard→sonnet,
economy→haiku). Override per tier if a model isn't on your plan, e.g.
`CTFSOLVER_FRONTIER=claude-cli:sonnet`. It calls `claude -p --output-format json` headlessly
with tools disabled, forcing subscription auth by dropping `ANTHROPIC_API_KEY` from the
child process (set `CTFSOLVER_CLAUDE_FORCE_SUB=0` to keep an API key instead).

Caveats, honestly: each call is a fresh CLI subprocess, so Claude Code re-sends its own
system prompt every time — calls are slower than the API and carry that overhead (which is
subscription-covered, so it doesn't count against the USD budget; call-count and time caps
still apply). For heavy use, the [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk/overview)
or a persistent session is the tidier path. This is the "for now" option.

## Watch it — the live console

Export any run's structured trace and replay it in the console UI:

```sh
PYTHONPATH=src python -m ctfsolver.cli solve --spec examples/repeating_xor/challenge.json --trace run.json
```

`run.json` holds the full event stream (every block span, the commands run, the generated
solver source, the verdict). The console (published separately as an artifact) replays it with
transport controls — the pipeline lane lights up block by block, the budget ledger fills, the
recovered flag and the generated solver appear — and it accepts your own exported traces by
drag-drop. `Trace.to_payload()` produces the same JSON programmatically.

## Measure it — the eval harness

Run the solver over a challenge set and get metrics you can tune against:

```sh
PYTHONPATH=src python -m ctfsolver.cli eval examples/suite --md eval.md --json eval.json
```

The bundled offline suite (`examples/suite/`) spans all categories. On the stub provider +
local sandbox it scores **5/7** — the crypto, misc, rev and forensics challenges solve
offline; pwn and web correctly show as misses (they need the container) rather than
inventing a flag. The report gives solve rate, points captured, cost/solve, time/solve, and
a per-category breakdown; `run_eval()` / `EvalReport` expose the same programmatically. Swap
the tiers (`--subscription`) or the sandbox to measure a real setup against this baseline.

## Writeups

Every solve closes with a shareable report: the flag, a summary, the recon, the numbered
approach, the exact commands, the **full generated solver** (captured from the trace, so
it's reproducible), the technique, and the cost. It's templated and deterministic by
default; set `CTFSOLVER_WRITEUP_LLM=1` to have the model polish the summary. The CLI saves
it to `writeups/<name>.md` (`--writeup PATH` to choose, `--no-writeup` to skip);
programmatically it's `report.writeup`. Unsolved challenges get an honest attempt log with
what was tried and what's still blocking.

## Live execution — run code, don't just plan

The point of the architecture is a single agent that can actually run code. A specialist
produces a solver or exploit and runs it in the sandbox via `specialists/runner.py`
(`run_script` → write it, execute it, extract the flag from stdout). The crypto specialist
does this offline today — give it `examples/repeating_xor/` (a multi-byte XOR the in-process
ladder can't crack) and it writes a solver, runs `python3 solve.py` in the sandbox, and
returns the verified flag. The pwn path writes a pwntools exploit and runs it against the
target — but only inside a real container (`ctx.sandbox.isolated`), since running a provided
binary is untrusted; on the offline host sandbox that step is refused and it falls back to a
plan. Build the toolchain image first (`docker/`):

```sh
docker build -f docker/toolbox.Dockerfile -t ctfsolver/toolbox:latest .
PYTHONPATH=src python -m ctfsolver.cli solve --spec challenge.json --container --subscription
```

## The pipeline

Orchestrator oversees; six stages carry a challenge; memory and guardrails run under all
of it.

| Stage | Tier | What it does |
|---|---|---|
| **Intake** | economy | target / file bundle / container → a normalized `Challenge` |
| **Triage** | economy·standard | classify category + first-contact recon + recall matching techniques |
| **Route** | standard | hand the **whole** challenge to the one best-fit specialist |
| **Solve** | frontier·standard | the specialist iterates in its sandbox until a flag appears |
| **Verify** | economy | the flag is the oracle: format regex + checker submission |
| **Learn** | economy | bank the technique, log the episode, write the writeup |

**Orchestrator** (frontier) runs many challenges at once by points-per-effort, tracks
budget/pressure, runs a bounded escalation ladder (retry → whole hand-off to a second
specialist → hint → human), and detects out-of-distribution challenges.

**Verify** submits to a real scoreboard when the challenge is configured for one. The
scoreboard is the operator's trusted endpoint, so the checker talks to it directly
(separate from the sandbox's target confinement) and the token stays out of the trace.
Configure it in the challenge spec — keep the token in an env var, not the file:

```json
{ "name": "sanity", "targets": ["nc chal.ctf 1337"], "files": ["./vuln"],
  "submission": { "kind": "ctfd", "endpoint": "https://ctf.example",
                  "challenge_id": 131, "extra": { "token_env": "CTFD_TOKEN" } } }
```

`kind` is `ctfd`, `rctf`, or `http` (a generic POST with `flag_field` / `success_contains`).
A `correct`/`goodFlag` verdict accepts, `already_solved` accepts, rate limits retry once;
anything else keeps the challenge unsolved. With no `submission`, Verify falls back to the
flag-format gate.

**Specialists** — `pwn`, `web`, `rev`, `crypto`, `forensics`, `misc` — each own a whole
challenge. `crypto` and `misc` solve classic encoding/weak-cipher challenges fully
offline today; the rest do what they can offline (strings/secret/magic-byte recon) and
lay out a concrete plan that runs once the container sandbox is enabled.

## What's real vs. what plugs in

The **control plane is complete and runs offline** on the standard library: models,
trace, memory (sqlite3 + FTS5), guardrails, intake/triage/route/verify, the orchestrator
with its scheduler and escalation ladder, and a working crypto/misc solver — all covered
by the test suite.

Two things are interfaces with stubs, by design, so CI needs no network or heavy tooling:

- **LLM** (`llm/`) — a deterministic `StubClient` backs every tier. Real providers live
  in `llm/providers.py`: the Anthropic/OpenAI API clients (`CTFSOLVER_FRONTIER=anthropic:claude-opus-4-8`
  plus the `providers` extra), and a **subscription provider** that routes calls through
  the local `claude` CLI so they run on your Claude subscription with no API key (below).
- **Sandbox** (`sandbox/`) — `LocalSandbox` runs a safe read-only tool allow-list and no
  real egress. `ContainerSandbox` runs the full toolchain in a disposable, hardened
  container with egress confined to the target at the network layer; it works over a
  real `DockerDriver` (daemon-gated) or an offline `LocalProcessDriver` for CI. The
  egress policy is derived from the scope and generates iptables/nftables rules — see
  `sandbox/egress.py`, tested for in/out of scope. Run with `--container` to opt in.

## Layout

```
src/ctfsolver/
  models.py config.py trace.py        # shared vocabulary, settings, structured trace
  llm/        base.py stub.py providers.py
  memory/     store.py seed.py         # procedural / episodic / conceptual / working (FTS5)
  guardrails/ scope.py budget.py audit.py gate.py
  sandbox/    base.py local.py
  pipeline/   intake.py triage.py route.py verify.py
  specialists/ base.py registry.py pwn.py web.py rev.py crypto.py forensics.py misc.py
  orchestrator.py cli.py
tests/        28 offline tests
docs/         THREAT_MODEL.md  SPECIALISTS.md
data/         techniques.json  (the seed technique library)
examples/toy_xor/                     (the offline demo challenge)
```

See [`docs/SPECIALISTS.md`](docs/SPECIALISTS.md) to add a specialist and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the stdlib-only / no-fragmentation rules.

## Roadmap

- **Sprint 3** — ✅ container sandbox with network-layer egress control; ✅ scoreboard
  checker adapters (CTFd / rCTF / generic HTTP); ✅ toolbox image + live execution
  (generate solver/exploit → run in the sandbox → read flag), with the crypto specialist
  solving live and the pwn path firing pwntools in the container; ✅ writeup generation at
  the Learn stage; ✅ live paths for rev/web/forensics (generate + run a solver, container-
  gated where it needs isolation or egress).
- **Sprint 4** — ✅ eval harness with solve-rate / cost / time metrics and a per-category
  breakdown; ✅ live console UI — `solve --trace run.json` exports the structured run trace,
  and the console replays it (pipeline lights up block by block, with the ledger, flag and
  generated solver). The project is feature-complete for the planned scope.
