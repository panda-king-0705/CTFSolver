"""Core domain models. Pure stdlib, no side effects, safe to import anywhere.

These dataclasses are the vocabulary every stage of the pipeline speaks. Keep them
free of behaviour that touches the network, the filesystem or an LLM -- that belongs
in the pipeline, guardrail and specialist modules.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Categories
# --------------------------------------------------------------------------- #
class Category(str, Enum):
    """CTF challenge categories. A challenge has exactly one primary category;
    a cross-category challenge is handed *whole* to a second specialist, never split.
    """

    PWN = "pwn"
    WEB = "web"
    REV = "rev"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    MISC = "misc"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, value: str) -> "Category":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.UNKNOWN


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------- #
# Target: something to interact with over the wire
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """A live endpoint the solver may interact with -- and *only* this endpoint.

    `kind` is "tcp" (host+port, e.g. `nc host port`), "http" (a url), or "none".
    `scope_key` is the canonical identity the scope guardrail allow-lists against.
    """

    kind: str
    host: Optional[str] = None
    port: Optional[int] = None
    url: Optional[str] = None
    raw: str = ""

    @property
    def scope_key(self) -> str:
        if self.kind == "tcp" and self.host:
            return f"{self.host}:{self.port}" if self.port else self.host
        if self.kind == "http" and self.url:
            return self.url
        return self.raw

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.kind == "tcp":
            return f"nc {self.host} {self.port}"
        if self.kind == "http":
            return self.url or ""
        return self.raw or "(no target)"


# --------------------------------------------------------------------------- #
# Artifact: a provided file to analyze
# --------------------------------------------------------------------------- #
@dataclass
class Artifact:
    """A handout file. `kind` is a coarse type hint (binary/pcap/image/source/...)."""

    path: str
    name: str = ""
    kind: str = "unknown"
    size: int = 0
    sha256: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name and self.path:
            self.name = self.path.replace("\\", "/").rsplit("/", 1)[-1]


# --------------------------------------------------------------------------- #
# Submission / checker info
# --------------------------------------------------------------------------- #
@dataclass
class Submission:
    """How to confirm a flag with the challenge's own checker, when one exists."""

    kind: str = "none"  # "none" | "regex" | "http" | "callback"
    endpoint: Optional[str] = None
    challenge_id: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Challenge: the normalized unit of work
# --------------------------------------------------------------------------- #
DEFAULT_FLAG_FORMAT = r"flag\{[^}]{1,256}\}"


@dataclass
class Challenge:
    """A challenge, normalized by intake. This is the only thing the operator must
    provide: a target and/or files (and optionally a container to spin up)."""

    name: str
    targets: list[Target] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    flag_format: str = DEFAULT_FLAG_FORMAT
    points: int = 100
    description: str = ""
    submission: Submission = field(default_factory=Submission)
    category_hint: Category = Category.UNKNOWN
    local_instance: Optional[str] = None  # e.g. a built container id/handle
    id: str = field(default_factory=lambda: _new_id("chal"))
    created_at: float = field(default_factory=time.time)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def scope_keys(self) -> list[str]:
        """Every endpoint this challenge is authorized to touch."""
        keys = [t.scope_key for t in self.targets if t.scope_key]
        if self.local_instance:
            keys.append(self.local_instance)
        return keys


# --------------------------------------------------------------------------- #
# Understanding: triage output
# --------------------------------------------------------------------------- #
@dataclass
class Understanding:
    """What triage concluded before a specialist commits effort."""

    category: Category = Category.UNKNOWN
    subtype: str = ""
    recon: list[str] = field(default_factory=list)
    candidate_techniques: list[str] = field(default_factory=list)
    score: float = 0.0  # confidence there is enough to act on, 0..1
    notes: str = ""


# --------------------------------------------------------------------------- #
# Flag + outcome
# --------------------------------------------------------------------------- #
@dataclass
class Flag:
    value: str
    source: str = ""  # where it was recovered, e.g. "remote shell: cat flag"
    verified: bool = False


class OutcomeStatus(str, Enum):
    SOLVED = "solved"
    BLOCKED = "blocked"  # stuck; went up the escalation ladder
    FAILED = "failed"  # budget/attempts spent without a flag
    WAITING = "waiting"  # handed to a second specialist / awaiting a human


@dataclass
class Outcome:
    """What a specialist (or the orchestrator) returns for one attempt."""

    status: OutcomeStatus
    flag: Optional[Flag] = None
    steps: list[str] = field(default_factory=list)
    notes: str = ""
    specialist: str = ""
    reroute_to: Optional[Category] = None  # set when status==WAITING for a hand-off
    hint_request: Optional[str] = None
    used_technique_ids: list[str] = field(default_factory=list)
    cost_usd: float = 0.0
    tool_calls: int = 0

    @property
    def solved(self) -> bool:
        return self.status is OutcomeStatus.SOLVED and self.flag is not None


@dataclass
class Attempt:
    """A recorded run of a specialist against a challenge (for episodic memory)."""

    challenge_id: str
    specialist: str
    outcome: Outcome
    started_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    id: str = field(default_factory=lambda: _new_id("att"))


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #
@dataclass
class Budget:
    """Hard caps for one challenge. The ledger (guardrails.budget) enforces these
    with reservations so a run can never silently overspend."""

    usd: float = 2.0
    tool_calls: int = 60
    wall_seconds: float = 900.0


# --------------------------------------------------------------------------- #
# Technique (procedural memory -- the library that compounds across events)
# --------------------------------------------------------------------------- #
@dataclass
class Technique:
    """A reusable solve skeleton. `pattern` is when to reach for it; `recipe` is the
    high-level approach. This is the system's moat: CTF techniques repeat heavily."""

    title: str
    category: Category
    pattern: str = ""
    recipe: str = ""
    tags: list[str] = field(default_factory=list)
    uses: int = 0
    wins: int = 0
    source: str = ""
    id: str = field(default_factory=lambda: _new_id("tech"))

    @property
    def win_rate(self) -> float:
        return (self.wins / self.uses) if self.uses else 0.0
