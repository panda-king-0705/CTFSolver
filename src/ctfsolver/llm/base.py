"""LLM client contract. The pipeline only ever asks for a *tier* (see config); a
factory maps the tier's model string to a concrete client. Everything is async so
the orchestrator can work many challenges at once while calls are in flight."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    text: str
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class LLMClient(Protocol):
    """Minimal surface every provider implements."""

    model: str

    async def complete(
        self,
        messages: list[Message],
        *,
        system: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> LLMResponse: ...


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: str) -> Any:
    """Tolerant JSON extraction: strips code fences, grabs the outermost object."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        m = _JSON_BLOCK.search(cleaned)
        if m:
            return json.loads(m.group(0))
        raise


async def complete_json(
    client: LLMClient,
    user: str,
    *,
    system: Optional[str] = None,
    max_tokens: int = 1024,
) -> tuple[Any, LLMResponse]:
    """Ask for JSON and parse it. Returns (parsed, raw_response)."""
    resp = await client.complete([Message("user", user)], system=system, max_tokens=max_tokens)
    return extract_json(resp.text), resp


def get_client(model: str, **kwargs: Any) -> LLMClient:
    """Factory: 'stub:economy' -> StubClient; 'anthropic:claude-...' / 'openai:gpt-...'
    -> real providers (imported lazily so missing SDKs never break the control plane)."""
    provider, _, rest = model.partition(":")
    provider = provider.lower()
    if provider == "stub":
        from .stub import StubClient

        return StubClient(model=rest or "economy")
    if provider in {"anthropic", "openai", "claude-cli", "subscription", "cc"}:
        from . import providers

        return providers.build(provider, rest, **kwargs)
    raise ValueError(f"unknown LLM provider in model string: {model!r}")
