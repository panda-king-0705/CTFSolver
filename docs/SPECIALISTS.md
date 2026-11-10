# Writing a Specialist

A **specialist** owns a whole CTF challenge, end to end, inside its sandbox. The
orchestrator classifies a challenge, routes it to exactly one specialist, and hands it
over whole. The specialist does recon, forms a hypothesis, builds an exploit or solver,
runs it in the sandbox, and returns an `Outcome`.

This guide is the contract for writing a new one. It is grounded in the real interface
in `src/ctfsolver/specialists/base.py` and the working `CryptoSpecialist` in
`specialists/crypto.py`.

---

## The core rule: whole-challenge ownership

The single most important rule, and the reason the architecture exists:

> Orchestrate centrally, but hand each challenge **whole** to one specialist with a real
> sandbox. Never split tightly-coupled exploit work across agents that cannot run code.

Exploit development is a tight loop: leak an address, compute an offset, rebuild the
payload, re-run, observe, adjust. Splitting that loop across agents that pass text to
each other and cannot execute breaks the thing that makes it work. So a specialist does
**not** delegate sub-pieces to other agents. It keeps the whole challenge, in one
sandbox, in one reasoning context.

The one exception is when a specialist discovers the challenge genuinely belongs to a
different category — then it performs a clean hand-off of the **whole** challenge (see
[Cross-category hand-off](#cross-category-hand-off)), never a split.

---

## The `Specialist` ABC

Subclass `Specialist`, set two class attributes, implement one async method, and
register it.

```python
from ..models import Category, Outcome
from .base import SolveContext, Specialist
from .registry import register

@register
class MySpecialist(Specialist):
    category = Category.WEB          # the one category this specialist owns
    name = "web-specialist"          # stable identifier, appears in Outcome + audit

    async def solve(self, ctx: SolveContext) -> Outcome:
        ...
```

- **`category: Category`** — which category this specialist owns. The registry holds one
  specialist per category (`registry.register` keys on `category`), and routing looks it
  up here. Categories are `PWN`, `WEB`, `REV`, `CRYPTO`, `FORENSICS`, `MISC`, `UNKNOWN`.
- **`name: str`** — a stable, human-readable identifier. It is stamped onto every
  `Outcome` this specialist returns and shows up in the audit trail and episodic memory.
- **`async def solve(self, ctx: SolveContext) -> Outcome`** — the entry point. All the
  work happens here (or in helpers it calls). It is `async` so the orchestrator can keep
  many challenges in flight while calls are outstanding.

### Optional: `fit_bonus`

```python
def fit_bonus(self, challenge, understanding) -> float:
    text = " ".join(understanding.recon + [understanding.subtype]).lower()
    return 0.15 if any(k in text for k in ("rsa", "xor", "cipher")) else 0.0
```

`fit_bonus` returns extra routing weight (0..1) beyond the plain category match. Override
it to claim a sub-type you are especially strong at. It defaults to `0.0`. Keep it
cheap — it runs during routing, before any sandbox work.

---

## `SolveContext` — everything you are handed

`solve` receives one argument, a `SolveContext`. Everything a specialist needs is on it;
scope, budget, and audit are already wired into the sandbox, so you rarely touch them
directly.

| Field | Type | What it is |
|---|---|---|
| `ctx.challenge` | `Challenge` | The normalized unit of work: `name`, `targets`, `artifacts`, `flag_format`, `description`, `submission`, `local_instance`, etc. |
| `ctx.understanding` | `Understanding` | What triage concluded: `category`, `subtype`, `recon` notes, `candidate_techniques`, a confidence `score`. |
| `ctx.sandbox` | `Sandbox` | Your execution environment. Read staged files, run tools, reach the network — all guardrailed. See below. |
| `ctx.memory` | `MemoryStore` | The four-store sqlite memory (procedural / episodic / conceptual / working), searchable via FTS5. |
| `ctx.trace` | `Trace` | Structured event log for the console and audit backbone. |
| `ctx.settings` | `Settings` | Runtime config: model tiers, stage routing, orchestration knobs. |
| `ctx.ledger` | `Ledger` | The budget ledger. Check `can_afford(...)` before expensive steps. |
| `ctx.techniques` | `list[Technique]` | Recalled solve skeletons relevant to this challenge — your hypotheses. |
| `ctx.scratch` | `dict[str, Any]` | A per-run blackboard for whatever you want to stash. |
| `ctx.llm(stage)` | `LLMClient` | Factory for a model client bound to a pipeline *stage* (see below). |

### `ctx.sandbox` — the guarded edge

The sandbox (`sandbox/base.py`) is where all real work happens, and it is where the
guardrails live:

- `ctx.sandbox.read_bytes(name)` / `write_bytes` / `stage_file` / `list_dir` — file I/O,
  confined to the sandbox workdir (a path that escapes raises `ScopeError`).
- `await ctx.sandbox.exec(argv, timeout=...)` — run a tool. Charges one tool call to the
  ledger and audits the command. Returns an `ExecResult` with `.ok`, `.stdout`, etc.
- `await ctx.sandbox.egress(host=..., port=..., url=..., note=...)` — the **only** way to
  touch the network. It calls `scope.check` first and raises `ScopeError` for any
  out-of-scope destination, then charges the ledger and audits the egress. You do not
  scope-check by hand; the sandbox does it for you, and you cannot bypass it.

### `ctx.llm(stage)` — reasoning by stage

You never name a concrete model. You ask for a **stage**, and config maps the stage to a
tier to a model (`config.py`, `DEFAULT_STAGE_TIERS`). Pass the stage that matches the
work:

```python
strategist = ctx.llm("solve_strategy")   # frontier tier: exploit chains, crypto math
scripter   = ctx.llm("solve_scripting")  # standard tier: writing the solver script
```

Stages include `triage_classify`, `triage_analysis`, `route`, `solve_strategy`,
`solve_scripting`, `verify_sanity`, and `learn`. This keeps hard reasoning on strong
models and routine work on cheap ones, automatically.

---

## Helpers on the base class

The base class gives you four helpers. Use them; do not construct `Outcome` objects by
hand.

### `self.find_flags(text, fmt) -> list[str]`

Extract flag candidates from text using the challenge's flag-format regex
(`ctx.challenge.flag_format`). Deduplicates, order-preserving, and swallows a bad regex
rather than raising. Call it on anything you decode or any tool output.

### `self.found(value, source, steps, **kw) -> Outcome`

Return a **SOLVED** outcome. `source` records where the flag came from (e.g.
`"base64-decode of cipher.txt"` or `"remote shell: cat flag"`) — this ends up in the
audit trail, so be specific. Pass `used_technique_ids=[...]` to credit a recalled
technique, and `cost_usd=...` if you tracked it.

### `self.blocked(notes, steps, *, hint=None, reroute_to=None, **kw) -> Outcome`

Return a **BLOCKED** outcome when you are stuck (e.g. a crypto challenge arrived with no
ciphertext). Pass `hint=` to request a specific hint up the escalation ladder. If you
pass `reroute_to=Category.X`, the status becomes **WAITING** and it is a hand-off, not a
dead end (see next section).

### `self.failed(notes, steps, **kw) -> Outcome`

Return a **FAILED** outcome when you exhausted your approach or your budget without a
flag. Say *why* in `notes` and, where useful, what a heavier approach would need — that
note is what the next attempt or a human reads.

---

## Cross-category hand-off

If, after looking, you conclude the challenge is really another category's problem, hand
the **whole** challenge off. Do not try to partially solve it and pass fragments.

```python
return self.blocked(
    "artifact is an ELF with a stack overflow; this is a pwn challenge, not rev",
    steps,
    reroute_to=Category.PWN,
)
```

`reroute_to` flips the outcome to `WAITING` and tells the orchestrator to route the
intact challenge to the named category's specialist, which then owns it whole. This is
the *only* sanctioned form of cross-specialist movement, and it preserves the
whole-challenge rule: one owner at a time, always complete.

---

## Budget discipline

Every `exec` and `egress` already charges the ledger, and `charge` raises
`BudgetExceeded` if a cap would be blown. Your job is to not blunder into that wall:
before an expensive step — a frontier-tier LLM call, a long brute force, a heavy tool —
check affordability and bail cleanly if you cannot pay for it.

```python
if not ctx.ledger.can_afford(usd=0.20, calls=3):
    return self.failed("insufficient budget for the lattice attack stage", steps)
```

`can_afford(usd=..., calls=...)` returns a bool; it does not charge. Prefer a clean
`BLOCKED`/`FAILED` over spinning until the ledger kills you mid-action. You can also read
`ctx.ledger.pressure` (0..1) and `snapshot()` to adapt — e.g. skip to a cheaper approach
as pressure rises.

---

## A minimal annotated specialist

This mirrors the real `CryptoSpecialist` shape — recon, hypothesis from a recalled
technique, build, run, check — stripped to the essentials.

```python
"""Example specialist: a trivial 'rev' specialist that reads a staged binary's
strings and looks for an exposed flag before escalating to real tooling."""
from __future__ import annotations

from ..models import Category, Outcome
from .base import SolveContext, Specialist
from .registry import register


@register                                   # self-register so routing can find us
class ExampleRevSpecialist(Specialist):
    category = Category.REV                  # the one category we own
    name = "example-rev-specialist"          # stable id, lands in Outcome + audit

    def fit_bonus(self, challenge, understanding) -> float:
        # claim a sub-type we are strong at; cheap, runs during routing
        sub = (understanding.subtype or "").lower()
        return 0.1 if "strings" in sub else 0.0

    async def solve(self, ctx: SolveContext) -> Outcome:
        fmt = ctx.challenge.flag_format      # the regex find_flags matches against
        steps: list[str] = []

        # Guard: a rev challenge needs a binary to work on.
        if not ctx.challenge.artifacts:
            return self.blocked(
                "rev challenge with no binary to analyze", steps,
                hint="need the challenge binary")

        for art in ctx.challenge.artifacts:
            # Read the staged file *through the sandbox* (confined to the workdir).
            data = ctx.sandbox.read_bytes(art.name)
            steps.append(f"read {art.name} ({len(data)} bytes)")

            # 1) Cheapest check first: is the flag sitting in the open?
            for flag in self.find_flags(data.decode("utf-8", "ignore"), fmt):
                return self.found(flag, f"strings of {art.name}", steps)

            # 2) Escalate to a real tool — but only if we can afford it.
            if not ctx.ledger.can_afford(usd=0.0, calls=1):
                return self.failed("out of budget before disassembly", steps)

            res = await ctx.sandbox.exec(["strings", "-n", "8", ctx.sandbox.path(art.name)])
            if res.ok:
                for flag in self.find_flags(res.stdout, fmt):
                    return self.found(flag, f"strings(1) of {art.name}", steps)

        # 3) Our approach is exhausted. If it smells like another category, hand off
        #    the WHOLE challenge; otherwise fail with a useful note.
        sub = (ctx.understanding.subtype or "").lower()
        if "packed" in sub or "upx" in sub:
            return self.blocked(
                "binary is packed; needs unpacking + deeper rev", steps,
                hint="try UPX unpack in the container sandbox")

        return self.failed(
            "no flag via strings; needs disassembly/decompilation in the "
            "container sandbox (ghidra/angr)", steps)
```

### What to copy from this shape

- **Cheapest checks first.** Look for the flag in the open before you reach for heavy
  tooling or a frontier model. The crypto and misc specialists both walk a ladder from
  trivial to expensive; follow that pattern.
- **Read and run only through `ctx.sandbox`.** Never touch the host filesystem or the
  network directly — the sandbox is where scope, budget, and audit are enforced.
- **Record `steps` as you go.** They are your human-readable account of the solve and
  travel with the `Outcome`.
- **End in exactly one of `found` / `blocked` / `failed`.** A specialist always returns a
  decisive `Outcome`; it never returns `None` or raises its way out of `solve`.

---

## Registering and loading

The `@register` decorator (`specialists/registry.py`) inserts your class into the
registry under its `category`. Bundled specialists are imported by
`registry.load_defaults()` so they self-register; if you add a new module, make sure it
is imported on that path (or wherever your deployment loads specialists) so the
decorator actually runs. Remember there is **one specialist per category** — registering
a second specialist for a category replaces the first.
