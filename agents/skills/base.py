"""Base skill class for the skills system."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseSkill(ABC):
    """Base class for all skills.
    
    Skills are modular capabilities that agents can load and use
    during execution. Each skill provides specific functionality
    like web search, reporting, proxy control, etc.
    """

    def __init__(self, name: str, description: str) -> None:
        """Initialize a skill.
        
        Args:
            name: Unique skill identifier
            description: Human-readable description of the skill
        """
        self.name = name
        self.description = description

    @abstractmethod
    async def execute(self, context: dict[str, Any], **kwargs: Any) -> Any:
        """Execute the skill with given context and parameters.
        
        Args:
            context: Execution context (target, findings, etc.)
            **kwargs: Skill-specific parameters
            
        Returns:
            Skill execution result
        """
        pass

    def can_handle(self, task_type: str) -> bool:
        """Check if this skill can handle a given task type.
        
        Args:
            task_type: Type of task to handle
            
        Returns:
            True if skill can handle this task type
        """
        return False

    def __repr__(self) -> str:
        return f"Skill(name={self.name!r}, description={self.description!r})"