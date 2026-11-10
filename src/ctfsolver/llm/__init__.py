"""LLM integration: a tiny async client contract, a deterministic stub, and a
factory that maps tier model strings to concrete providers."""
from __future__ import annotations

from .base import (  # noqa: F401
    LLMClient,
    LLMResponse,
    Message,
    complete_json,
    extract_json,
    get_client,
)
from .stub import StubClient  # noqa: F401

__all__ = [
    "LLMClient",
    "LLMResponse",
    "Message",
    "StubClient",
    "complete_json",
    "extract_json",
    "get_client",
]
