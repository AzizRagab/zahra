"""Skill registry for managing and discovering skills."""

from __future__ import annotations

from .base import BaseSkill


class SkillRegistry:
    """Registry for managing skills.
    
    Provides centralized registration, discovery, and retrieval
    of skills for agents.
    """

    def __init__(self) -> None:
        """Initialize an empty skill registry."""
        self._skills: dict[str, BaseSkill] = {}

    def register(self, skill: BaseSkill) -> None:
        """Register a skill in the registry.
        
        Args:
            skill: Skill instance to register
            
        Raises:
            ValueError: If a skill with the same name already exists
        """
        if skill.name in self._skills:
            raise ValueError(f"Skill '{skill.name}' is already registered")
        self._skills[skill.name] = skill

    def get(self, name: str) -> BaseSkill | None:
        """Get a skill by name.
        
        Args:
            name: Skill name to retrieve
            
        Returns:
            Skill instance or None if not found
        """
        return self._skills.get(name)

    def list_names(self) -> list[str]:
        """List all registered skill names.
        
        Returns:
            List of skill names
        """
        return list(self._skills.keys())

    def list_skills(self) -> list[BaseSkill]:
        """List all registered skills.
        
        Returns:
            List of skill instances
        """
        return list(self._skills.values())

    def get_by_capability(self, task_type: str) -> list[BaseSkill]:
        """Get all skills that can handle a specific task type.
        
        Args:
            task_type: Type of task to find skills for
            
        Returns:
            List of skills that can handle the task
        """
        return [skill for skill in self._skills.values() if skill.can_handle(task_type)]

    def clear(self) -> None:
        """Remove all registered skills."""
        self._skills.clear()

    def __len__(self) -> int:
        return len(self._skills)

    def __contains__(self, name: str) -> bool:
        return name in self._skills

    def __repr__(self) -> str:
        return f"SkillRegistry(skills={list(self._skills.keys())})"