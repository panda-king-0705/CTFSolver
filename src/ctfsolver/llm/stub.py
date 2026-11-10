"""Deterministic, offline LLM stub. It lets the control plane and tests run with no
network and no API keys, while exercising the exact async interface a real provider
implements. Register canned answers with `.script(substring, reply)`; unmatched
prompts get a minimal valid-JSON reply so JSON-expecting stages still parse."""
from __future__ import annotations

from typing import Optional

from .base import LLMResponse, Message

# A tiny fixed "cost" per call so the budget ledger has something real to meter.
_STUB_COST = {"frontier": 0.004, "standard": 0.001, "economy": 0.0002, "checker": 0.0002}


class StubClient:
    def __init__(self, model: str = "economy") -> None:
        self.model = f"stub:{model}"
        self._tier = model or "economy"
        self._scripts: list[tuple[str, str]] = []
        self.calls = 0

    def script(self, substring: str, reply: str) -> "StubClient":
        """Return `reply` whenever the prompt contains `substring`. Chainable."""
        self._scripts.append((substring.lower(), reply))
        return self

    async def complete(
        self,
        messages: list[Message],
        *,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> LLMResponse:
        self.calls += 1
        joined = " ".join(m.content for m in messages).lower()
        if system:
            joined = system.lower() + " " + joined
        reply = '{"ok": true, "stub": true}'
        for needle, canned in self._scripts:
            if needle in joined:
                reply = canned
                break
        cost = _STUB_COST.get(self._tier, 0.0002)
        return LLMResponse(
            text=reply,
            cost_usd=cost,
            input_tokens=len(joined) // 4,
            output_tokens=len(reply) // 4,
            model=self.model,
            meta={"stub": True},
        )
