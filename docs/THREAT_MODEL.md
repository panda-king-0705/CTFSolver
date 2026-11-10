# Threat Model and Responsible Use

`ctfsolver` is an autonomous system that solves Capture-the-Flag (CTF) challenges.
It takes a challenge as little as a connection string (`nc host port`), a URL, or a
handout file, reasons about it, and runs real exploitation tooling inside a sandbox
until it recovers the flag.

The same machinery that solves a CTF pwnable can, pointed at a production system,
attack it. This document states that dual-use reality plainly, describes the controls
built to keep the tool on the right side of it, and sets out what the operator — the
human running it — is responsible for. Read it before you run the solver against
anything, and read it again before you fork it.

---

## 1. Intended use

The solver is built for, and only for:

- **CTF challenges.** Jeopardy and attack-defense CTFs, practice wargames, and
  purpose-built vulnerable targets (challenge containers you were handed or stood up
  yourself). These exist to be exploited; that is the whole point of them.
- **Explicitly authorized penetration testing.** Engagements where a specific,
  identified scope has been authorized **in writing** by someone with the authority to
  grant it, and where the authorization covers the exact hosts, ports, and URLs the
  solver will touch.

Both cases share one property that the entire design leans on: **there is a bounded,
pre-agreed set of endpoints the tool is allowed to interact with, and everything else
is off-limits.** The solver is engineered to respect that boundary mechanically rather
than on its best behavior.

## 2. Out of scope — do not use this for

The following are **not** supported uses, and the controls below are designed to
refuse or at least surface them:

- Testing, scanning, or exploiting any system you do not own or have **written**
  authorization to test. "I'm pretty sure it's fine" is not authorization.
- Any activity against third-party infrastructure, shared hosting, or cloud tenants
  where your authorization does not clearly extend to the specific target.
- Exfiltrating data, establishing persistence, pivoting, or any destructive action,
  even against an in-scope host, unless the engagement rules of engagement explicitly
  permit it and a human has approved it at the gate.
- Using a CTF framing ("it's just a challenge I set up") to launder an attack on a
  system that is not actually yours.

If you are not certain a use is in scope, it is out of scope.

## 3. The dual-use concern, stated plainly

An autonomous exploit-development loop does not know, on its own, whether the host on
the other end of the socket is a throwaway challenge container or someone's payroll
server. The capability is identical in both cases. Automation also removes the natural
friction — the time, effort, and moments of hesitation — that normally sits between a
person and a harmful action.

We do not pretend a prompt or a policy file makes misuse impossible. What we **can**
do, and have done, is:

1. Make the authorized scope an explicit, machine-checked object rather than an
   assumption.
2. Enforce that scope at a layer the model cannot talk its way past.
3. Confine every action to a disposable sandbox.
4. Cap resource spend so a runaway loop stops.
5. Record everything that ran, append-only, so an operator can review it.
6. Stop and ask a human before anything out-of-scope, destructive, or sensitive.

The controls are defense-in-depth. None is sufficient alone; together they make the
honest path the path of least resistance and make misuse loud instead of silent.

---

## 4. Guardrails

Guardrails are first-class components, not afterthoughts bolted onto the prompt. Each
lives in `src/ctfsolver/guardrails/` and is part of the control plane, which runs on
the Python standard library alone and is fully testable offline.

### 4.1 Scope confinement — default-deny allow-list

`guardrails/scope.py` defines `ScopePolicy`: a **default-deny** allow-list built from
the challenge's own declared targets (`ScopePolicy.for_challenge`). Only the hosts,
host:port pairs, HTTP origins, and local-instance handles that the challenge names are
permitted. Everything else is refused by `ScopePolicy.check`, which raises `ScopeError`
and reports both the rejected target and the authorized scope.

**Why it is enforced at the network layer, not just in the prompt.** A policy the model
is merely *told* to follow is a suggestion; a sufficiently clever prompt, a confused
chain of reasoning, or a malicious challenge description can argue its way around a
suggestion. So scope is checked at the one chokepoint every outbound action must pass
through: the sandbox's `egress` method (`sandbox/base.py`) calls `scope.check(...)`
*before* any network action, and refuses out-of-scope destinations. The module's own
docstring states the design intent: the policy is the single source of truth, and in
production **the same allow-list is also enforced at the container's network layer**,
so the solver literally cannot open a socket to an out-of-scope address — the OS drops
it regardless of what the model decided to do. The prompt-level understanding of scope
and the OS-level enforcement of scope are two expressions of one policy; the second
exists because the first is not trustworthy on its own.

A refused egress is not silent: it is written to the audit log as `egress_refused` and
it pings the human gate as an `out_of_scope` event.

### 4.2 Sandbox isolation — disposable containers

A specialist never runs tools in the host environment. It works entirely inside a
`Sandbox` (`sandbox/base.py`):

- `LocalSandbox` (offline) runs a safe allow-list of read-only tools and performs no
  real network egress — this is what CI and offline development use.
- `ContainerSandbox` runs the full exploitation toolchain inside a **disposable
  container** whose network egress is allow-listed to the target at the OS level, and
  which is torn down after the challenge.

Filesystem access is confined too: `Sandbox.path` resolves every path against the
sandbox workdir and raises `ScopeError` if a path tries to escape it. Handout files are
staged in explicitly. The container is the blast-radius boundary: whatever the solver
does, it does inside something cheap to destroy and isolated from the operator's
machine and network.

### 4.3 Budget — a reservation ledger

`guardrails/budget.py` enforces a per-challenge `Budget` (USD, tool-call count,
wall-clock seconds) through a reservation `Ledger`. Before every billable action the
caller asks `can_afford(...)`; after it completes the caller `charge`s the actual cost.
The sandbox charges a tool call on every `exec` and every `egress`, so spend cannot
drift untracked. If an action would exceed a cap, `charge` raises `BudgetExceeded`
rather than letting the run quietly overspend. The ledger also exposes a `pressure`
signal (0..1) the orchestrator uses to favor cheaper approaches as limits approach.

Budget is a safety control as much as a cost control: a bounded run is a run that
cannot loop forever hammering a target.

### 4.4 Audit trail — append-only

`guardrails/audit.py` keeps an **append-only** `AuditLog`. Every command executed,
every network egress (allowed *and* refused), every model call, and every gate decision
is recorded with an actor, an action, a detail, structured data, and a timestamp, and
can be serialized as JSONL (`to_jsonl`). It can tee into the live `Trace` so the
console and the audit share one stream. For a security tool, the record of what ran is
as important as the result — it is the artifact an operator reviews to confirm the run
stayed in bounds, and the evidence if it did not.

### 4.5 Human gate — stop for a person

`guardrails/gate.py` defines the `HumanGate`. A fixed set of action kinds —
`out_of_scope`, `destructive`, `exfiltrate`, `write_external`, `legal_sensitive` —
**must never run without an explicit human yes.** The gate's `check` returns `ALLOWED`
for ordinary actions, and for sensitive ones returns `APPROVED` only if the approver
affirmatively says yes, otherwise `DENIED`.

The default approver **denies everything** (`_deny_all`). This is deliberate: in
autonomous or CI mode, with no human present to approve, the safe path is the default
path. You have to wire in a real approver to get a yes, and even then only for the
specific sensitive action in front of it.

---

## 5. What the operator is responsible for

The controls above constrain the tool. They do not make the operator optional. Running
this solver means owning the following:

- **Authorization.** You are responsible for having genuine, written authorization for
  every target before you point the solver at it. The tool cannot verify your legal
  right to test a host; only you can, and you are accountable for it. CTF challenges you
  were given or stood up yourself satisfy this trivially; anything else requires a
  signed scope.
- **Scope definition.** You define the challenge targets, and therefore the allow-list.
  If you put a host in scope, you are asserting you are authorized to attack it. Define
  scope narrowly and correctly. Do not add a host "just in case."
- **Reviewing the audit trail.** The append-only log exists to be read. After a run —
  and especially before trusting the tool in a new environment — review what actually
  executed, what egress happened, and what the gate was asked to approve. The audit
  trail is only a control if someone looks at it.
- **Staffing the gate.** If you enable a non-denying approver, a competent human must
  be behind it, understand what they are approving, and have the authority to approve
  it. An auto-approver defeats the gate.
- **Operating environment.** Run the container sandbox with its OS-level egress
  controls actually in place. The network-layer enforcement is only real if you deploy
  it; the policy object alone is the belt, the container firewall is the suspenders.

## 6. If you fork this — a checklist

Forking or extending the solver means you inherit the responsibility for its controls.
Before you run a fork against anything that is not a disposable challenge you own:

- [ ] **Keep scope default-deny.** Do not add a "scan everything" or wildcard mode.
      Every target must be explicitly allow-listed per challenge.
- [ ] **Keep enforcement at the network layer.** If you swap sandboxes, confirm the new
      one actually enforces the scope allow-list at the OS/container level on egress —
      not just that it calls `scope.check`. A sandbox that trusts the model to self-police
      is not a sandbox.
- [ ] **Do not weaken the default-deny gate.** If you add an approver, make a human the
      approver. Never ship an auto-approve for `out_of_scope`, `destructive`,
      `exfiltrate`, `write_external`, or `legal_sensitive`.
- [ ] **Keep the audit log append-only and complete.** If you add a new action that
      touches the network, the filesystem outside the sandbox, or an external system,
      record it. Do not add code paths that act without being audited.
- [ ] **Keep the budget caps.** A new specialist or tool must charge the ledger for its
      actions and check `can_afford` before expensive ones. An uncapped loop is a
      liability.
- [ ] **Do not add out-of-scope capability.** Features like mass scanning, credential
      spraying, or targeting from a list of hosts are not CTF features; they are attack
      features. Leave them out.
- [ ] **Preserve the intended-use boundary in your docs and UX.** Make it obvious to
      your users that this is for CTFs and authorized testing only, and make the
      authorized-scope requirement unavoidable.

If a change makes misuse easier, quieter, or the default, it is the wrong change.
