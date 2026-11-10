"""Real LLM providers, behind the same async contract as the stub.

The control plane never imports these at module load -- the factory
(`llm.base.get_client`) imports this module lazily, and each client imports its SDK
only when constructed. So CI and offline runs stay on the stub with no SDK installed,
and swapping to a real model is a config change (e.g. CTFSOLVER_FRONTIER=anthropic:claude-opus-4-8)
with the `providers` extra installed and an API key in the environment.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Optional

from .base import LLMResponse, Message

# Approximate USD per 1M tokens (input, output). Override via `prices=` if needed;
# these are only used to meter the budget ledger, not to bill anyone.
_PRICES: dict[str, tuple[float, float]] = {
    # anthropic
    "claude-opus-4-8": (15.0, 75.0),
    "claude-sonnet-5-5": (3.0, 15.0),
    "claude-haiku-5-5": (0.80, 4.0),
    # openai
    "gpt-6.1-sol": (2.5, 10.0),
    "gpt-6-luna": (0.50, 1.50),
}


def _cost(model: str, in_tok: int, out_tok: int, prices: dict) -> float:
    pin, pout = prices.get(model, (3.0, 15.0))
    return (in_tok * pin + out_tok * pout) / 1_000_000


class AnthropicClient:
    def __init__(self, model: str, *, prices: Optional[dict] = None, **kwargs: Any) -> None:
        self.model = model
        self._prices = prices or _PRICES
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover - needs the optional extra
            raise RuntimeError(
                "anthropic SDK not installed. `pip install 'ctfsolver[providers]'` "
                "and set ANTHROPIC_API_KEY."
            ) from exc
        from anthropic import AsyncAnthropic

        self._client = AsyncAnthropic(**kwargs)

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2) -> LLMResponse:  # pragma: no cover
        resp = await self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system or "",
            messages=[{"role": m.role, "content": m.content} for m in messages],
        )
        text = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        itok = resp.usage.input_tokens
        otok = resp.usage.output_tokens
        return LLMResponse(text=text, cost_usd=_cost(self.model, itok, otok, self._prices),
                           input_tokens=itok, output_tokens=otok, model=self.model)


class OpenAIClient:
    def __init__(self, model: str, *, prices: Optional[dict] = None, **kwargs: Any) -> None:
        self.model = model
        self._prices = prices or _PRICES
        try:
            import openai  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "openai SDK not installed. `pip install 'ctfsolver[providers]'` "
                "and set OPENAI_API_KEY."
            ) from exc
        from openai import AsyncOpenAI

        self._client = AsyncOpenAI(**kwargs)

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2) -> LLMResponse:  # pragma: no cover
        msgs = ([{"role": "system", "content": system}] if system else []) + \
               [{"role": m.role, "content": m.content} for m in messages]
        resp = await self._client.chat.completions.create(
            model=self.model, max_tokens=max_tokens, temperature=temperature, messages=msgs,
        )
        text = resp.choices[0].message.content or ""
        usage = resp.usage
        itok = getattr(usage, "prompt_tokens", 0)
        otok = getattr(usage, "completion_tokens", 0)
        return LLMResponse(text=text, cost_usd=_cost(self.model, itok, otok, self._prices),
                           input_tokens=itok, output_tokens=otok, model=self.model)


class ClaudeCLIProvider:
    """Route completions through the local `claude` CLI (Claude Code) so they run on the
    user's Claude subscription instead of a pay-per-token API key -- no API billing to set
    up. It calls `claude -p --output-format json` headlessly in a neutral working
    directory with tools disabled, so each call is a plain completion.

    Requirements: Claude Code installed and logged in with a subscription (`claude login`).
    Notes: `max_tokens`/`temperature` aren't exposed by the CLI (model defaults apply);
    each subprocess is a fresh session, so Claude Code's own system prompt is re-sent per
    call (the reported `cost_usd` is the list-price equivalent, covered by the
    subscription). For many calls prefer the Agent SDK or a persistent session.
    """

    def __init__(
        self,
        model: str = "",
        *,
        bin: str = "claude",
        force_subscription: Optional[bool] = None,
        timeout: float = 180.0,
    ) -> None:
        self._model_arg = model  # "" -> the CLI's default model
        self.model = f"claude-cli:{model or 'default'}"
        self._bin = shutil.which(bin) or bin
        env_force = os.getenv("CTFSOLVER_CLAUDE_FORCE_SUB", "1") != "0"
        self._force_sub = env_force if force_subscription is None else force_subscription
        self._timeout = timeout

    def available(self) -> bool:
        try:
            r = subprocess.run([self._bin, "--version"], capture_output=True, timeout=10)
            return r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _flatten(messages: list[Message]) -> str:
        parts = []
        for m in messages:
            parts.append(m.content if m.role == "user" else f"[{m.role}] {m.content}")
        return "\n\n".join(parts)

    async def complete(self, messages, *, system=None, max_tokens=1024, temperature=0.2) -> LLMResponse:
        argv = [self._bin, "-p", self._flatten(messages),
                "--output-format", "json", "--allowed-tools", ""]
        if self._model_arg:
            argv += ["--model", self._model_arg]
        if system:
            argv += ["--system-prompt", system]
        env = os.environ.copy()
        if self._force_sub:
            env.pop("ANTHROPIC_API_KEY", None)  # force the logged-in subscription, not API billing
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=tempfile.gettempdir(), env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("claude -p timed out")
        if proc.returncode != 0:
            raise RuntimeError(f"claude -p failed ({proc.returncode}): "
                               f"{err.decode('utf-8', 'replace')[:300]}")
        try:
            data = json.loads(out.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"claude -p: unparseable output: {exc}") from exc
        if data.get("is_error"):
            raise RuntimeError(f"claude -p error: {str(data.get('result'))[:300]}")
        usage = data.get("usage") or {}
        model = next(iter(data.get("modelUsage", {})), self.model)
        list_cost = float(data.get("total_cost_usd", 0.0) or 0.0)
        # Subscription calls are covered by the plan, so they don't spend the USD budget;
        # the call-count and wall-clock caps still apply. The list-price equivalent is
        # kept in meta for visibility.
        return LLMResponse(
            text=data.get("result", ""),
            cost_usd=0.0 if self._force_sub else list_cost,
            input_tokens=int(usage.get("input_tokens", 0) or 0),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
            model=model,
            meta={"via": "claude-cli", "subscription": self._force_sub,
                  "list_cost_usd": round(list_cost, 4)},
        )


def build_cli(model: str, **kwargs: Any) -> ClaudeCLIProvider:
    return ClaudeCLIProvider(model, **kwargs)


def build(provider: str, model: str, **kwargs: Any):
    if provider == "anthropic":
        return AnthropicClient(model, **kwargs)
    if provider == "openai":
        return OpenAIClient(model, **kwargs)
    if provider in ("claude-cli", "subscription", "cc"):
        return ClaudeCLIProvider(model, **kwargs)
    raise ValueError(f"unknown provider: {provider}")
