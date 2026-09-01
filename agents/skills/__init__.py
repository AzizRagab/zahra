"""Skills system for agents.

Provides modular capabilities that agents can load and use during execution.
Inspired by Strix's skills system.
"""

from __future__ import annotations

from .base import BaseSkill
from .registry import SkillRegistry
from .http_headers_scanner import HTTPHeadersScannerSkill

__all__ = ["BaseSkill", "SkillRegistry", "HTTPHeadersScannerSkill"]

# Global skill registry
_registry = SkillRegistry()

# Register default skills
_registry.register(HTTPHeadersScannerSkill())


def register_skill(skill: BaseSkill) -> None:
    """Register a skill globally."""
    _registry.register(skill)


def get_skill(name: str) -> BaseSkill | None:
    """Get a skill by name."""
    return _registry.get(name)


def list_skills() -> list[str]:
    """List all registered skill names."""
    return _registry.list_names()