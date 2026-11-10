"""Specialist registry: one specialist per category. Route looks up here."""
from __future__ import annotations

from typing import Optional

from ..models import Category
from .base import Specialist

_REGISTRY: dict[Category, Specialist] = {}


def register(cls: type[Specialist]) -> type[Specialist]:
    """Class decorator: instantiate the specialist once and register the instance by
    category. Returns the class unchanged so the name still binds to the class."""
    _REGISTRY[cls.category] = cls()
    return cls


def get(category: Category) -> Optional[Specialist]:
    return _REGISTRY.get(category)


def all_specialists() -> dict[Category, Specialist]:
    return dict(_REGISTRY)


def load_defaults() -> None:
    """Import the bundled specialists so they self-register. Idempotent."""
    from . import crypto, forensics, misc, pwn, rev, web  # noqa: F401
