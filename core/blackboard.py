"""Stigmergic blackboard for agent coordination.

Provides a shared findings board with pheromone-based coordination
inspired by Pentest-Swarm-AI's blackboard architecture.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine

logger = logging.getLogger("zahra.core.blackboard")


class FindingType(str, Enum):
    """Types of findings that can be written to the blackboard."""
    RECON = "recon"
    PORT_OPEN = "port_open"
    HTTP_ENDPOINT = "http_endpoint"
    TECHNOLOGY = "technology"
    CVE_MATCH = "cve_match"
    MISCONFIGURATION = "misconfiguration"
    EXPLOIT_CHAIN = "exploit_chain"
    EXPLOIT_RESULT = "exploit_result"
    CAMPAIGN_COMPLETE = "campaign_complete"
    AGENT_ERROR = "agent_error"


@dataclass
class Finding:
    """A finding written to the blackboard."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    agent_name: str = ""
    type: FindingType = FindingType.RECON
    target: str = ""
    data: bytes = b""
    pheromone_base: float = 1.0
    half_life_sec: int = 3600  # 1 hour default
    created_at: datetime = field(default_factory=datetime.now)
    
    @property
    def pheromone(self) -> float:
        """Calculate current pheromone level based on decay."""
        age_sec = (datetime.now() - self.created_at).total_seconds()
        decay_factor = 0.5 ** (age_sec / self.half_life_sec)
        return self.pheromone_base * decay_factor


@dataclass
class Budget:
    """Campaign budget tracker."""
    max_tokens: int = 500_000
    max_agent_hours: float = 2.0
    tokens_used: int = 0
    agent_hours_used: float = 0.0
    
    def exceeded(self) -> bool:
        """Check if budget is exceeded."""
        return (
            self.tokens_used >= self.max_tokens
            or self.agent_hours_used >= self.max_agent_hours
        )
    
    def remaining(self) -> dict[str, Any]:
        """Get remaining budget."""
        return {
            "tokens": max(0, self.max_tokens - self.tokens_used),
            "hours": max(0.0, self.max_agent_hours - self.agent_hours_used),
        }


class Blackboard:
    """Stigmergic blackboard for agent coordination.
    
    Agents coordinate by reading and writing findings to this shared board.
    Each finding has a pheromone weight that biases other agents toward it
    and decays over time, so stale paths die naturally.
    """

    def __init__(self) -> None:
        """Initialize an empty blackboard."""
        self._findings: list[Finding] = []
        self._subscriptions: list[tuple[Predicate, Callable[[Finding], Coroutine[Any, Any, None]]]] = []
        self._budgets: dict[str, Budget] = {}

    def write(self, finding: Finding) -> Finding:
        """Write a finding to the blackboard.
        
        Args:
            finding: Finding to write
            
        Returns:
            The written finding with assigned ID
        """
        if not finding.id:
            finding.id = str(uuid.uuid4())
        
        self._findings.append(finding)
        logger.debug(
            "Finding written: %s (pheromone=%.2f)",
            finding.type.value,
            finding.pheromone,
        )
        
        # Notify subscribers
        self._notify(finding)
        
        return finding

    def subscribe(
        self,
        predicate: Predicate,
        callback: Callable[[Finding], Coroutine[Any, Any, None]],
    ) -> None:
        """Subscribe to findings matching a predicate.
        
        Args:
            predicate: Predicate to match findings
            callback: Async callback to invoke when finding matches
        """
        self._subscriptions.append((predicate, callback))
        logger.debug("New subscription: %s", predicate)

    def _notify(self, finding: Finding) -> None:
        """Notify subscribers of a new finding."""
        for predicate, _callback in self._subscriptions:
            if predicate.matches(finding):
                logger.debug("Notifying subscriber for finding %s", finding.id)
                # In production, this would invoke _callback asynchronously
                # For now, just log it

    def query(self, predicate: Predicate) -> list[Finding]:
        """Query findings matching a predicate.
        
        Args:
            predicate: Predicate to match
            
        Returns:
            List of matching findings sorted by pheromone (descending)
        """
        matches = [f for f in self._findings if predicate.matches(f)]
        matches.sort(key=lambda f: f.pheromone, reverse=True)
        return matches

    def get_budget(self, campaign_id: str) -> Budget:
        """Get or create budget for a campaign."""
        if campaign_id not in self._budgets:
            self._budgets[campaign_id] = Budget()
        return self._budgets[campaign_id]

    def update_budget(self, campaign_id: str, duration_hours: float, tokens: int) -> None:
        """Update campaign budget usage."""
        budget = self.get_budget(campaign_id)
        budget.agent_hours_used += duration_hours
        budget.tokens_used += tokens

    def clear(self) -> None:
        """Clear all findings."""
        self._findings.clear()
        logger.info("Blackboard cleared")


@dataclass
class Predicate:
    """Predicate for matching findings."""
    types: list[FindingType] | None = None
    min_pheromone: float = 0.0
    agent_name: str = ""
    since_id: str = ""
    limit: int = 0
    
    def __post_init__(self) -> None:
        """Validate predicate after initialization."""
        if self.types is None:
            self.types = []

    def matches(self, finding: Finding) -> bool:
        """Check if a finding matches this predicate."""
        if self.types and finding.type not in self.types:
            return False
        if self.min_pheromone and finding.pheromone < self.min_pheromone:
            return False
        if self.agent_name and finding.agent_name != self.agent_name:
            return False
        if self.since_id and finding.id <= self.since_id:
            return False
        return True
