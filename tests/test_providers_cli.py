"""Subscription provider wiring. These stay offline (no live `claude` calls in the suite,
to not spend subscription quota); a live round-trip is exercised separately."""
from __future__ import annotations

from ctfsolver.config import Tier, subscription_tier_models
from ctfsolver.llm.base import get_client
from ctfsolver.llm.providers import ClaudeCLIProvider


def test_factory_routes_subscription_schemes():
    c = get_client("claude-cli:sonnet")
    assert isinstance(c, ClaudeCLIProvider) and "sonnet" in c.model
    assert isinstance(get_client("subscription:opus"), ClaudeCLIProvider)
    assert isinstance(get_client("cc:haiku"), ClaudeCLIProvider)


def test_subscription_tier_models_point_at_cli():
    tiers = subscription_tier_models()
    assert tiers[Tier.FRONTIER].startswith("claude-cli:")
    assert tiers[Tier.ECONOMY] == "claude-cli:haiku"


def test_cli_available_returns_bool():
    # must not raise whether or not `claude` is installed/logged in
    assert isinstance(ClaudeCLIProvider().available(), bool)


def test_flatten_messages():
    from ctfsolver.llm.base import Message

    out = ClaudeCLIProvider._flatten([Message("user", "hello"), Message("assistant", "hi")])
    assert "hello" in out and "[assistant] hi" in out
