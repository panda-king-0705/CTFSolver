"""Configuration: model tiers, stage routing, and runtime knobs.

Mirrors the BrainEngine's tiered model config and STAGE_ROUTING, but all defaults
resolve to the deterministic stub provider so the control plane runs offline.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum


class Tier(str, Enum):
    """Reasoning tiers. Which concrete model backs each tier is a deployment choice;
    the pipeline only ever asks for a tier."""

    FRONTIER = "frontier"  # hard strategy: exploit chains, crypto math, orchestration
    STANDARD = "standard"  # routine specialist work, recon analysis, scripting
    ECONOMY = "economy"  # triage classify, summarize, flag-format matching
    CHECKER = "checker"  # kept for parity; CTF verification is mostly mechanical


# Stage -> tier. A stage can be re-pointed via the CTFSOLVER_STAGE_ROUTING env var
# (JSON: {"solve": "standard", ...}), exactly like the Brain's STAGE_ROUTING.
DEFAULT_STAGE_TIERS: dict[str, Tier] = {
    "triage_classify": Tier.ECONOMY,
    "triage_analysis": Tier.STANDARD,
    "route": Tier.STANDARD,
    "solve_strategy": Tier.FRONTIER,
    "solve_scripting": Tier.STANDARD,
    "verify_sanity": Tier.ECONOMY,
    "learn": Tier.ECONOMY,
}


def subscription_tier_models(
    frontier: str = "opus", standard: str = "sonnet",
    economy: str = "haiku", checker: str = "haiku",
) -> dict["Tier", str]:
    """Point every tier at the local `claude` CLI so model calls run on the user's Claude
    subscription. Override a tier's alias if a model isn't on your plan
    (e.g. CTFSOLVER_FRONTIER=claude-cli:sonnet)."""
    return {
        Tier.FRONTIER: f"claude-cli:{frontier}",
        Tier.STANDARD: f"claude-cli:{standard}",
        Tier.ECONOMY: f"claude-cli:{economy}",
        Tier.CHECKER: f"claude-cli:{checker}",
    }


@dataclass
class Settings:
    # Which provider backs each tier. "stub" is offline & deterministic.
    tier_models: dict[Tier, str] = field(
        default_factory=lambda: {
            Tier.FRONTIER: os.getenv("CTFSOLVER_FRONTIER", "stub:frontier"),
            Tier.STANDARD: os.getenv("CTFSOLVER_STANDARD", "stub:standard"),
            Tier.ECONOMY: os.getenv("CTFSOLVER_ECONOMY", "stub:economy"),
            Tier.CHECKER: os.getenv("CTFSOLVER_CHECKER", "stub:checker"),
        }
    )
    stage_tiers: dict[str, Tier] = field(default_factory=lambda: dict(DEFAULT_STAGE_TIERS))

    # Orchestration
    max_concurrent: int = int(os.getenv("CTFSOLVER_MAX_CONCURRENT", "4"))
    rework_rounds: int = int(os.getenv("CTFSOLVER_REWORK_ROUNDS", "1"))
    max_escalations: int = int(os.getenv("CTFSOLVER_MAX_ESCALATIONS", "3"))

    # Multi-model racing (the ctf-agent swarm): when the specialists come up empty, race
    # these models on the WHOLE challenge in parallel -- first flag wins. Empty = no swarm
    # (use single-model metacognition). e.g. CTFSOLVER_SWARM="claude-cli:opus,claude-cli:sonnet"
    swarm_models: list[str] = field(default_factory=lambda: [
        m.strip() for m in os.getenv("CTFSOLVER_SWARM", "").split(",") if m.strip()
    ])
    # >1 runs waves: between waves a coordinator reads the transcripts and guides the next.
    swarm_waves: int = int(os.getenv("CTFSOLVER_SWARM_WAVES", "1"))

    # Guardrails
    allow_human_gate: bool = True
    db_path: str = os.getenv("CTFSOLVER_DB", ":memory:")

    # Learn stage: polish the writeup summary with the learn-tier model (costs a call)
    writeup_llm: bool = os.getenv("CTFSOLVER_WRITEUP_LLM", "0") == "1"

    def __post_init__(self) -> None:
        raw = os.getenv("CTFSOLVER_STAGE_ROUTING")
        if raw:
            try:
                override = json.loads(raw)
                for stage, tier in override.items():
                    self.stage_tiers[stage] = Tier(tier)
            except (ValueError, KeyError):
                pass  # bad override is ignored, like the Brain's tolerant parsing

    def tier_for(self, stage: str) -> Tier:
        return self.stage_tiers.get(stage, Tier.ECONOMY)

    def model_for(self, stage: str) -> str:
        return self.tier_models[self.tier_for(stage)]
