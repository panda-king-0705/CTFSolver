"""Append-only audit log. For a security tool the record of what ran is as important
as the result. Every command, model call and gate decision lands here, and it can tee
into the live Trace so the console and the audit share one stream."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..trace import Trace


@dataclass
class AuditRecord:
    actor: str  # "sandbox" | "llm" | "gate" | "orchestrator" | specialist name
    action: str  # "exec" | "egress" | "llm_call" | "gate" | "flag" ...
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    challenge_id: Optional[str] = None
    ts: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(
            {"ts": round(self.ts, 3), "actor": self.actor, "action": self.action,
             "detail": self.detail, "data": self.data, "chal": self.challenge_id}
        )


class AuditLog:
    def __init__(self, trace: Optional[Trace] = None, challenge_id: Optional[str] = None) -> None:
        self.records: list[AuditRecord] = []
        self._trace = trace
        self.challenge_id = challenge_id

    def record(self, actor: str, action: str, detail: str = "", **data: Any) -> AuditRecord:
        rec = AuditRecord(actor, action, detail, data, self.challenge_id)
        self.records.append(rec)
        if self._trace is not None:
            self._trace.emit(f"audit:{actor}", action, detail, **data)
        return rec

    def to_jsonl(self) -> str:
        return "\n".join(r.to_json() for r in self.records)
