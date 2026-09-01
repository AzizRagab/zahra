"""Agentic Core - The brain that manages the entire pentest swarm.

This is the central coordinator that:
1. Monitors the Blackboard for new findings
2. Distributes tasks to specialized agents
3. Decides when to start Exploit based on Scan results
4. Manages the overall campaign strategy
5. Learns from past campaigns via RAG

Inspired by:
- Strix's AgentCoordinator
- Pentest-Swarm-AI's Scheduler
- OmniRoute's dynamic routing
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.blackboard import Blackboard, Finding, FindingType, Predicate
from core.events import Event, EventEmitter, EventType, get_emitter
from core.memory import MemoryStore

logger = logging.getLogger("zahra.core.agentic_core")


class AgentRole(str, Enum):
    """Roles that agents can play in the swarm."""
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    REPORT = "report"


class TaskPriority(str, Enum):
    """Priority levels for tasks."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Task:
    """A task assigned to an agent."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: AgentRole = AgentRole.RECON
    target: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    context: dict[str, Any] = field(default_factory=dict)
    trigger_finding_id: str | None = None
    created_at: float = field(default_factory=time.time)
    assigned_at: float | None = None
    started_at: float | None = None
    completed_at: float | None = None
    status: str = "pending"  # pending, assigned, running, completed, failed


@dataclass
class CampaignState:
    """Persistent state for a campaign."""
    campaign_id: str
    status: str = "running"
    current_phase: str = "recon"
    completed_phases: list[str] = field(default_factory=list)
    active_tasks: list[str] = field(default_factory=list)
    completed_tasks: list[str] = field(default_factory=list)
    findings_count: int = 0
    started_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "status": self.status,
            "current_phase": self.current_phase,
            "completed_phases": self.completed_phases,
            "active_tasks": self.active_tasks,
            "completed_tasks": self.completed_tasks,
            "findings_count": self.findings_count,
            "started_at": self.started_at,
            "last_updated": self.last_updated,
        }


class AgenticCore:
    """The brain of the pentest swarm.
    
    This is the central coordinator that manages the entire campaign:
    - Monitors the Blackboard for new findings
    - Distributes tasks to specialized agents
    - Decides when to transition between phases
    - Learns from past campaigns via RAG
    - Emits events for observability
    """

    def __init__(
        self,
        blackboard: Blackboard,
        memory: MemoryStore,
        event_emitter: EventEmitter | None = None,
    ) -> None:
        self.blackboard = blackboard
        self.memory = memory
        self.event_emitter = event_emitter or get_emitter()
        
        self._campaign_states: dict[str, CampaignState] = {}
        self._task_queue: list[Task] = []
        self._active_campaigns: dict[str, asyncio.Task[Any]] = {}
        self._lock = threading.RLock()
        self._running = False
        self._monitor_task: asyncio.Task[Any] | None = None

    def start(self) -> None:
        """Start the agentic core."""
        if self._running:
            return
        
        self._running = True
        self._emit_event(EventType.CAMPAIGN_STARTED, "", detail="Agentic Core started")
        logger.info("Agentic Core started")

    def stop(self) -> None:
        """Stop the agentic core."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
        self._emit_event(EventType.CAMPAIGN_COMPLETE, "", detail="Agentic Core stopped")
        logger.info("Agentic Core stopped")

    def register_campaign(self, campaign_id: str) -> CampaignState:
        """Register a new campaign with the core."""
        with self._lock:
            state = CampaignState(campaign_id=campaign_id)
            self._campaign_states[campaign_id] = state
            logger.info("Registered campaign: %s", campaign_id)
            return state

    def get_campaign_state(self, campaign_id: str) -> CampaignState | None:
        """Get the state of a campaign."""
        with self._lock:
            return self._campaign_states.get(campaign_id)

    def update_campaign_phase(self, campaign_id: str, phase: str) -> None:
        """Update the current phase of a campaign."""
        with self._lock:
            state = self._campaign_states.get(campaign_id)
            if state is None:
                return
            
            if state.current_phase not in state.completed_phases:
                state.completed_phases.append(state.current_phase)
            
            state.current_phase = phase
            state.last_updated = time.time()
            
            self._emit_event(
                EventType.CAMPAIGN_STARTED,
                campaign_id,
                detail=f"Phase: {phase}"
            )

    def submit_task(self, task: Task) -> None:
        """Submit a task to the queue."""
        with self._lock:
            self._task_queue.append(task)
            logger.debug("Task submitted: %s (priority=%s)", task.id, task.priority)

    def get_next_task(self, role: AgentRole) -> Task | None:
        """Get the next task for a specific agent role."""
        with self._lock:
            # Filter by role and priority
            eligible = [
                t for t in self._task_queue
                if t.role == role and t.status == "pending"
            ]
            
            if not eligible:
                return None
            
            # Sort by priority and creation time
            priority_order = {
                TaskPriority.CRITICAL: 0,
                TaskPriority.HIGH: 1,
                TaskPriority.MEDIUM: 2,
                TaskPriority.LOW: 3,
            }
            eligible.sort(key=lambda t: (priority_order[t.priority], t.created_at))
            
            task = eligible[0]
            task.status = "assigned"
            task.assigned_at = time.time()
            
            return task

    def complete_task(self, task_id: str, findings_count: int = 0) -> None:
        """Mark a task as completed."""
        with self._lock:
            for task in self._task_queue:
                if task.id == task_id:
                    task.status = "completed"
                    task.completed_at = time.time()
                    
                    # Update campaign state
                    if task.trigger_finding_id:
                        # Find campaign from context
                        campaign_id = task.context.get("campaign_id")
                        if campaign_id and campaign_id in self._campaign_states:
                            state = self._campaign_states[campaign_id]
                            state.findings_count += findings_count
                            state.last_updated = time.time()
                    
                    logger.debug("Task completed: %s", task_id)
                    break

    def should_start_exploit(self, campaign_id: str) -> bool:
        """Decide whether to start the exploit phase.
        
        Logic:
        1. Check if scan phase has completed
        2. Check if there are exploitable findings on the blackboard
        3. Query RAG for similar past successful exploits
        4. Return True if conditions are met
        """
        with self._lock:
            state = self._campaign_states.get(campaign_id)
            if state is None:
                return False
            
            # Must have completed scan phase
            if "scan" not in state.completed_phases:
                return False
            
            # Check for exploitable findings
            predicate = Predicate(
                types=[FindingType.CVE_MATCH, FindingType.MISCONFIGURATION],
                min_pheromone=0.5,
            )
            exploitable = self.blackboard.query(predicate)
            
            if not exploitable:
                logger.info("No exploitable findings yet for campaign %s", campaign_id)
                return False
            
            # Query RAG for past successful exploits
            # This is a simplified version - in production, use proper RAG query
            rag_guidance = self._query_rag_for_exploit_guidance(exploitable)
            
            logger.info(
                "Exploit decision for %s: %d exploitable findings, RAG guidance: %s",
                campaign_id,
                len(exploitable),
                rag_guidance,
            )
            
            return len(exploitable) > 0

    def _query_rag_for_exploit_guidance(self, findings: list[Finding]) -> str:
        """Query the RAG system for exploit guidance based on similar past findings."""
        if not findings:
            return "no_findings"
        
        # Query memory for similar past exploits
        keywords = [f.type.value for f in findings[:3]]
        past_entries = self.memory.recall_relevant(keywords)
        
        if not past_entries:
            return "no_past_experience"
        
        # Check if past exploits were successful
        successful = sum(1 for e in past_entries if e.metadata.get("success", False))
        
        if successful > len(past_entries) / 2:
            return "proceed_with_exploitation"
        
        return "proceed_with_caution"

    def _emit_event(self, event_type: EventType, campaign_id: str, detail: str = "") -> None:
        """Emit an event."""
        self.event_emitter.emit(Event(
            type=event_type,
            campaign_id=campaign_id,
            detail=detail,
        ))

    def status(self) -> dict[str, Any]:
        """Get the status of the agentic core."""
        with self._lock:
            return {
                "running": self._running,
                "campaigns": len(self._campaign_states),
                "active_campaigns": len(self._active_campaigns),
                "pending_tasks": sum(1 for t in self._task_queue if t.status == "pending"),
                "active_tasks": sum(1 for t in self._task_queue if t.status in ("assigned", "running")),
                "completed_tasks": sum(1 for t in self._task_queue if t.status == "completed"),
            }