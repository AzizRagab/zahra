"""Orchestrator — the brain that distributes commands to the swarm.

The orchestrator sits at the top of the zahra stack. It receives a command
(either from the CLI or the API), asks the :class:`Router` to classify it,
then hands the resulting :class:`RouteDecision` to the
:class:`SwarmManager` which dispatches the actual agents.

Design notes
------------
* **No central planner** — inspired by Pentest-Swarm-AI's stigmergic
  swarm, the orchestrator does not micro-manage agent execution. It
  sets up the campaign, registers agents, and lets the swarm coordinator
  drive the rest.
* **Budget aware** — the orchestrator enforces token and wall-clock
  budgets. When a budget is exceeded it signals the swarm to wind down
  gracefully and produce a partial report.
* **Observable** — every campaign emits structured events that the CLI
  / API can subscribe to for live progress.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from core.agentic_core import AgenticCore
from core.blackboard import Blackboard
from core.events import Event, EventEmitter, EventType, get_emitter
from core.memory import Finding, MemoryStore
from core.router import Intent, RouteDecision, Router

logger = logging.getLogger("zahra.core.orchestrator")


class CampaignStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    BUDGET_EXCEEDED = "budget_exceeded"


@dataclass
class Campaign:
    """A single pentest campaign.

    Attributes:
        id: Unique campaign identifier.
        command: The original user command.
        target: Normalized target.
        intent: Classified intent from the router.
        status: Current campaign status.
        created_at: Unix timestamp.
        started_at: When execution began.
        finished_at: When execution ended.
        findings: Findings discovered during the campaign.
        events: Structured events emitted during execution.
        error: Error message if the campaign failed.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    command: str = ""
    target: str = ""
    intent: Intent = Intent.UNKNOWN
    status: CampaignStatus = CampaignStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    finished_at: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "command": self.command,
            "target": self.target,
            "intent": self.intent.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [f.to_dict() for f in self.findings],
            "events": list(self.events),
            "error": self.error,
        }


@dataclass
class Budget:
    """Resource budget for a campaign.

    Attributes:
        max_tokens: Maximum LLM tokens.
        max_agent_hours: Maximum wall-clock agent time in hours.
        tokens_used: Tokens consumed so far.
        agent_hours_used: Agent hours consumed so far.
    """

    max_tokens: int = 500_000
    max_agent_hours: float = 2.0
    tokens_used: int = 0
    agent_hours_used: float = 0.0

    def exceeded(self) -> bool:
        return self.tokens_used > self.max_tokens or self.agent_hours_used > self.max_agent_hours

    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.tokens_used)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_tokens": self.max_tokens,
            "max_agent_hours": self.max_agent_hours,
            "tokens_used": self.tokens_used,
            "agent_hours_used": self.agent_hours_used,
            "exceeded": self.exceeded(),
        }


class Orchestrator:
    """Top-level coordinator for the zahra platform.

    The orchestrator wires together the router, memory, and swarm manager.
    It is the single entry point that both the CLI and API call into.
    """

    def __init__(
        self,
        *,
        router: Router | None = None,
        memory: MemoryStore | None = None,
        swarm_manager: Any | None = None,
        budget: Budget | None = None,
        blackboard: Blackboard | None = None,
        event_emitter: EventEmitter | None = None,
        agentic_core: AgenticCore | None = None,
    ) -> None:
        self.router = router or Router()
        self.memory = memory or MemoryStore()
        self.swarm_manager = swarm_manager
        self.budget = budget or Budget()
        self.blackboard = blackboard or Blackboard()
        self.event_emitter = event_emitter or get_emitter()
        self.agentic_core = agentic_core
        self._campaigns: dict[str, Campaign] = {}
        self._lock = threading.RLock()
        self._event_subscribers: list[Callable[[str, dict[str, Any]], None]] = []

    # -- campaign management ----------------------------------------------

    def create_campaign(self, command: str) -> Campaign:
        """Create a campaign from a user command (does not start it)."""
        decision = self.router.route(command)
        campaign = Campaign(
            command=command,
            target=decision.target,
            intent=decision.intent,
        )
        with self._lock:
            self._campaigns[campaign.id] = campaign
        
        # Register with agentic core
        if self.agentic_core:
            self.agentic_core.register_campaign(campaign.id)
        
        # Emit event
        self._emit_event(EventType.CAMPAIGN_STARTED, campaign.id, detail=f"Target: {decision.target}")
        
        self._emit(campaign.id, "campaign_created", {"command": command, "target": decision.target})
        logger.info("created campaign %s for target '%s'", campaign.id, decision.target)
        return campaign

    def run_campaign(self, campaign_id: str) -> Campaign:
        """Execute a campaign by dispatching to the swarm manager."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ValueError(f"unknown campaign: {campaign_id}")
            if campaign.status == CampaignStatus.RUNNING:
                raise RuntimeError(f"campaign {campaign_id} is already running")

        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = time.time()
        self._emit(campaign_id, "campaign_started", {"intent": campaign.intent.value})

        try:
            # Start agentic core if available
            if self.agentic_core:
                self.agentic_core.start()
            
            decision = self.router.route(campaign.command)
            findings = self._dispatch(campaign, decision)
            campaign.findings.extend(findings)

            # Persist findings to memory.
            for f in findings:
                self.memory.record_finding(f)

            campaign.status = CampaignStatus.COMPLETED
            self._emit(campaign_id, "campaign_completed", {"findings": len(findings)})
        except Exception as exc:
            campaign.status = CampaignStatus.FAILED
            campaign.error = str(exc)
            self._emit(campaign_id, "campaign_error", {"error": str(exc)})
            logger.exception("campaign %s failed", campaign_id)
        finally:
            campaign.finished_at = time.time()
            self._charge_budget(campaign)
            
            # Stop agentic core
            if self.agentic_core:
                self.agentic_core.stop()

        return campaign

    async def run_campaign_async(self, campaign_id: str) -> Campaign:
        """Execute a campaign asynchronously (non-blocking for the API).

        This is the async twin of :meth:`run_campaign`. It dispatches to
        the swarm manager's ``execute_async`` so the event loop stays free
        and the API can stream live events over WebSocket.
        """
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                raise ValueError(f"unknown campaign: {campaign_id}")
            if campaign.status == CampaignStatus.RUNNING:
                raise RuntimeError(f"campaign {campaign_id} is already running")

        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = time.time()
        self._emit(campaign_id, "campaign_started", {"intent": campaign.intent.value})

        try:
            decision = self.router.route(campaign.command)
            if self.swarm_manager is not None and hasattr(self.swarm_manager, "execute_async"):
                findings = await self.swarm_manager.execute_async(
                    campaign, decision, self.memory, self.budget
                )
            else:
                # Fall back to the synchronous path in a thread.
                findings = await asyncio.to_thread(
                    self._dispatch, campaign, decision
                )
            campaign.findings.extend(findings)

            for f in findings:
                self.memory.record_finding(f)

            campaign.status = CampaignStatus.COMPLETED
            self._emit(campaign_id, "campaign_completed", {"findings": len(findings)})
        except Exception as exc:
            campaign.status = CampaignStatus.FAILED
            campaign.error = str(exc)
            self._emit(campaign_id, "campaign_error", {"error": str(exc)})
            logger.exception("campaign %s failed", campaign_id)
        finally:
            campaign.finished_at = time.time()
            self._charge_budget(campaign)

        return campaign

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def list_campaigns(self) -> list[Campaign]:
        with self._lock:
            return list(self._campaigns.values())

    # -- dispatch ----------------------------------------------------------

    def _dispatch(self, campaign: Campaign, decision: RouteDecision) -> list[Finding]:
        """Dispatch the campaign to the swarm manager.

        If no swarm manager is configured, we run a minimal local fallback
        so the platform is usable out-of-the-box for testing.
        """
        if self.swarm_manager is not None:
            return self.swarm_manager.execute(campaign, decision, self.memory, self.budget)

        # Local fallback — produce a placeholder finding so the pipeline
        # is end-to-end testable without external tools.
        logger.warning("no swarm manager configured; using local fallback")
        self._emit(campaign.id, "fallback_mode", {"reason": "no swarm manager"})
        return [
            Finding(
                agent_name="orchestrator",
                finding_type="info",
                target=campaign.target,
                severity="info",
                description=f"Placeholder finding for target '{campaign.target}'. "
                f"Configure a swarm manager to get real results.",
                confidence=0.1,
            )
        ]

    # -- budget ------------------------------------------------------------

    def _charge_budget(self, campaign: Campaign) -> None:
        elapsed_hours = 0.0
        if campaign.started_at and campaign.finished_at:
            elapsed_hours = (campaign.finished_at - campaign.started_at) / 3600.0
            self.budget.agent_hours_used += elapsed_hours
        
        # Update blackboard budget
        self.blackboard.update_budget(campaign.id, elapsed_hours, 0)
        
        if self.budget.exceeded():
            self._emit(campaign.id, "budget_exceeded", self.budget.to_dict())
            self._emit_event(EventType.BUDGET_EXCEEDED, campaign.id, detail="Budget exceeded")

    # -- events ------------------------------------------------------------

    def subscribe(self, callback: Callable[[str, dict[str, Any]], None]) -> None:
        self._event_subscribers.append(callback)

    def _emit(self, campaign_id: str, event_type: str, data: dict[str, Any]) -> None:
        event_data: dict[str, Any] = {"type": event_type, "timestamp": time.time(), **data}
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is not None:
                campaign.events.append(event_data)
        for callback in self._event_subscribers:
            try:
                callback(campaign_id, event_data)
            except Exception:
                logger.exception("event subscriber failed")
    
    def _emit_event(self, event_type: EventType, campaign_id: str, detail: str = "") -> None:
        """Emit a structured event."""
        self.event_emitter.emit(Event(
            type=event_type,
            campaign_id=campaign_id,
            detail=detail,
        ))

    # -- summary -----------------------------------------------------------

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "campaigns": len(self._campaigns),
                "active": sum(
                    1 for c in self._campaigns.values() if c.status == CampaignStatus.RUNNING
                ),
                "completed": sum(
                    1
                    for c in self._campaigns.values()
                    if c.status == CampaignStatus.COMPLETED
                ),
                "budget": self.budget.to_dict(),
                "memory": self.memory.summary(),
            }