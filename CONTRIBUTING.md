# Contributing

`ctfsolver` is an autonomous CTF solver built on the **BrainEngine** design:
orchestrate centrally, but solve each challenge *whole* in a confined sandbox. Before
contributing, read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (what this tool is and
is not for, and the guardrails) and [`docs/SPECIALISTS.md`](docs/SPECIALISTS.md) (the
specialist contract).

---

## Project layout

Everything lives under `src/ctfsolver/`:

| Package | Responsibility |
|---|---|
| `llm/` | LLM client contract (`base.py`), the offline deterministic `stub`, and the provider factory. The pipeline asks for a *stage*; config maps stage → tier → model. |
| `memory/` | The four-store sqlite memory — procedural (techniques), episodic (attempts), conceptual (durable facts), working (per-challenge blackboard) — searchable with FTS5. |
| `guardrails/` | The first-class safety layer: `scope` (default-deny allow-list), `budget` (reservation ledger), `audit` (append-only log), `gate` (human approval). |
| `sandbox/` | The execution contract. `LocalSandbox` runs offline read-only tools; `ContainerSandbox` runs the full toolchain in a disposable, network-confined container. |
| `pipeline/` | Central orchestration: intake, triage, routing, the solve loop, verification, and learning. |
| `specialists/` | The whole-challenge owners: `pwn`, `web`, `rev`, `crypto`, `forensics`, `misc`, plus the `registry` and the `base` ABC. |

Top-level `models.py`, `config.py`, and `trace.py` hold the shared vocabulary, runtime
settings, and the structured trace that every stage runs inside.

---

## The control-plane rule: stdlib-only, offline-testable

**The control plane must run on the Python standard library alone, and must stay fully
testable offline.**

- Core `dependencies` in `pyproject.toml` are intentionally empty. The control plane
  uses only the stdlib — `sqlite3` + FTS5 for memory, `asyncio` for orchestration.
- Real LLM providers (`anthropic`, `openai`), pwn tooling (`pwntools`), and other heavy
  machinery are **optional extras** (`[project.optional-dependencies]`), pulled in only
  when real exploitation or real models are wired up.
- Defaults resolve to the deterministic `stub` provider and the `LocalSandbox`, so the
  whole pipeline runs — and CI runs green — with nothing installed.

Practically, this means: do not add a third-party import to any control-plane module
(models, config, trace, pipeline, memory, guardrails, the specialist base/registry, the
LLM contract). If a feature needs a heavy library, put it behind an optional extra and a
lazy import (see how `llm/base.py:get_client` imports providers only when asked), so a
missing SDK never breaks the control plane. Anything on the core path must import and run
with an empty dependency set.

---

## Running the tests

```sh
pip install -e ".[dev]"   # pytest only
pytest
```

Tests must pass with **no** optional extras installed — that is the point of the
stdlib-only control plane. `pyproject.toml` already points pytest at `src/` and `tests/`,
so a plain `pytest` from the repo root is all you need. If a test needs a real provider
or real tooling to run, it is testing the wrong layer; test against the stub and the
local sandbox.

---

## Definition of Done

A change is done when:

- [ ] It runs on the **stdlib-only** control plane — no new core dependency, heavy
      libraries behind optional extras and lazy imports.
- [ ] `pytest` passes from a clean checkout with only `[dev]` installed.
- [ ] New network, filesystem-outside-sandbox, or external actions go **through the
      sandbox** so they are scope-checked, budget-charged, and audited — never around it.
- [ ] Budget is respected: expensive steps check `ctx.ledger.can_afford(...)` and bail
      cleanly; new actions charge the ledger.
- [ ] The guardrails' defaults stay safe: scope default-deny, the human gate denies by
      default for sensitive actions, the audit log stays append-only and complete.
- [ ] Behavior is covered by a test that runs offline.
- [ ] Docstrings explain intent, and `docs/` is updated if you changed a contract.

---

## The no-fragmentation design rule

This is the architecture's core correction and it is not negotiable:

> **A challenge is handed whole to one specialist with a real sandbox. Never split
> tightly-coupled exploit work across agents that cannot run code.**

Exploit development is a tight observe-adjust loop; fragmenting it across text-passing
agents breaks it. So:

- One specialist owns one challenge, end to end, in one sandbox.
- A specialist does **not** sub-delegate pieces of a challenge to other agents.
- The only cross-specialist movement is a clean hand-off of the **whole** challenge via
  `return self.blocked(..., reroute_to=Category.X)` when it belongs to another category.

Contributions that reintroduce fragmentation — splitting a solve across agents, routing
sub-tasks out to models that cannot execute, or breaking the single-owner rule — will be
rejected. Orchestrate centrally; solve whole.
