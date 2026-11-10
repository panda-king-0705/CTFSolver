"""Structured trace. Every stage runs inside a BlockSpan, so a run reads as the
whole diagram being walked -- not just the LLM calls. This is the console's source
and the audit record's backbone (ctfsolver.brain.block, in the Brain's terms)."""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional


@dataclass
class TraceEvent:
    block: str
    kind: str  # "start" | "end" | "note" | "cmd" | "flag" | "error"
    text: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    challenge_id: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "ts": round(self.ts, 3),
                "block": self.block,
                "kind": self.kind,
                "text": self.text,
                "data": self.data,
                "chal": self.challenge_id,
            }
        )


class Trace:
    """An append-only event log. Subscribe with `on(...)` to stream to a console."""

    def __init__(self, challenge_id: Optional[str] = None) -> None:
        self.challenge_id = challenge_id
        self.events: list[TraceEvent] = []
        self._subs: list[Callable[[TraceEvent], None]] = []

    def on(self, fn: Callable[[TraceEvent], None]) -> None:
        self._subs.append(fn)

    def emit(self, block: str, kind: str, text: str = "", **data: Any) -> TraceEvent:
        ev = TraceEvent(block=block, kind=kind, text=text, data=data, challenge_id=self.challenge_id)
        self.events.append(ev)
        for fn in self._subs:
            try:
                fn(ev)
            except Exception:  # a broken subscriber must never break a solve
                pass
        return ev

    def note(self, block: str, text: str, **data: Any) -> None:
        self.emit(block, "note", text, **data)

    def cmd(self, block: str, command: str, **data: Any) -> None:
        self.emit(block, "cmd", command, **data)

    def flag(self, block: str, value: str, **data: Any) -> None:
        self.emit(block, "flag", value, **data)

    @contextmanager
    def span(self, block: str, text: str = "") -> Iterator["Trace"]:
        self.emit(block, "start", text)
        t0 = time.time()
        try:
            yield self
        except Exception as exc:
            self.emit(block, "error", f"{type(exc).__name__}: {exc}")
            raise
        finally:
            self.emit(block, "end", "", seconds=round(time.time() - t0, 3))

    def blocks_touched(self) -> list[str]:
        seen: list[str] = []
        for e in self.events:
            if e.kind == "start" and e.block not in seen:
                seen.append(e.block)
        return seen

    def to_payload(self, *, challenge: str = "", summary: Optional[dict] = None) -> dict:
        """Full run trace as a JSON-ready dict -- the data the console UI replays. Times
        are relative to the first event so a replay is self-contained."""
        t0 = self.events[0].ts if self.events else 0.0
        return {
            "challenge": challenge,
            "challenge_id": self.challenge_id,
            "summary": summary or {},
            "events": [
                {
                    "t": round(e.ts - t0, 3),
                    "block": e.block,
                    "kind": e.kind,
                    "text": e.text,
                    "data": e.data,
                }
                for e in self.events
            ],
        }
