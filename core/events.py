"""Event system for platform observability.

Provides structured event emission and logging for tracking
agent activities, budget usage, and campaign progress.
Inspired by Pentest-Swarm-AI's event system.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("zahra.core.events")


class EventType(str, Enum):
    """Types of events that can be emitted."""
    AGENT_STARTED = "agent_started"
    AGENT_FINISHED = "agent_finished"
    AGENT_ERROR = "agent_error"
    AGENT_BUDGET_EXCEEDED = "agent_budget_exceeded"
    AGENT_BUDGET_WARN = "agent_budget_warn"
    CAMPAIGN_STARTED = "campaign_started"
    CAMPAIGN_COMPLETE = "campaign_complete"
    CAMPAIGN_ERROR = "campaign_error"
    BUDGET_EXCEEDED = "budget_exceeded"
    FINDING_WRITTEN = "finding_written"
    SKILL_EXECUTED = "skill_executed"
    TOOL_USED = "tool_used"


@dataclass
class Event:
    """Structured event emitted by the platform."""
    type: EventType
    timestamp: datetime = field(default_factory=datetime.now)
    campaign_id: str = ""
    agent_name: str = ""
    finding_id: str = ""
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict[str, Any])

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "type": self.type.value,
            "timestamp": self.timestamp.isoformat(),
            "campaign_id": self.campaign_id,
            "agent_name": self.agent_name,
            "finding_id": self.finding_id,
            "detail": self.detail,
            "metadata": self.metadata,
        }


class EventEmitter:
    """Event emitter for platform observability.
    
    Provides structured logging and optional callbacks for
    real-time event monitoring.
    """

    def __init__(self) -> None:
        """Initialize the event emitter."""
        self._listeners: dict[EventType, list[Callable[[Event], None]]] = {}
        self._global_listeners: list[Callable[[Event], None]] = []

    def on(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        """Register a listener for a specific event type.
        
        Args:
            event_type: Type of event to listen for
            callback: Function to call when event is emitted
        """
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)

    def on_any(self, callback: Callable[[Event], None]) -> None:
        """Register a listener for all events.
        
        Args:
            callback: Function to call for any event
        """
        self._global_listeners.append(callback)

    def off(self, event_type: EventType, callback: Callable[[Event], None]) -> None:
        """Unregister a listener.
        
        Args:
            event_type: Type of event
            callback: Function to remove
        """
        if event_type in self._listeners:
            self._listeners[event_type] = [
                cb for cb in self._listeners[event_type] if cb != callback
            ]
        if callback in self._global_listeners:
            self._global_listeners.remove(callback)

    def emit(self, event: Event) -> None:
        """Emit an event.
        
        Args:
            event: Event to emit
        """
        # Log the event
        self._log_event(event)
        
        # Notify specific listeners
        if event.type in self._listeners:
            for callback in self._listeners[event.type]:
                try:
                    callback(event)
                except Exception as exc:
                    logger.error("Event listener error: %s", exc, exc_info=True)
        
        # Notify global listeners
        for callback in self._global_listeners:
            try:
                callback(event)
            except Exception as exc:
                logger.error("Global event listener error: %s", exc, exc_info=True)

    def _log_event(self, event: Event) -> None:
        """Log an event with appropriate severity."""
        log_data = {
            "event_type": event.type.value,
            "campaign_id": event.campaign_id,
            "agent_name": event.agent_name,
            "finding_id": event.finding_id,
            "detail": event.detail,
        }
        
        if event.type in (EventType.AGENT_ERROR, EventType.CAMPAIGN_ERROR, 
                          EventType.BUDGET_EXCEEDED, EventType.AGENT_BUDGET_EXCEEDED):
            logger.warning("Event: %s", log_data)
        else:
            logger.info("Event: %s", log_data)


# Global event emitter
_emitter = EventEmitter()


def get_emitter() -> EventEmitter:
    """Get the global event emitter."""
    return _emitter


def emit(event: Event) -> None:
    """Emit an event using the global emitter."""
    _emitter.emit(event)