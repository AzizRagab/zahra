"""Zahra — Personal Operator-Directed Controller Model

The **ZahraController** is the personal, ultimate controller that governs
every subsystem of the zahra Agentic Pentest System.  It is:

* **Personal** (``مودل خاص بي`` / "my personal model") — configurable
  per-operator with personalized RAG memory, preferred tools, and custom
  system prompts.
* **The controller** (``ال هو المتحكك`` / "the one that controls") — a
  single entry-point that owns the orchestrator, swarm manager, agentic
  core, AI agent, blackboard, memory, events, database, and LLM wrapper.
* **Without LLaMA** (``بدون استخدام الواما``) — the LLM backend is
  validated at construction time; any LLaMA-derived model is silently
  rejected and replaced with a safe non-LLaMA alternative (Mistral,
  Gemma, Phi, Qwen …).
* **Operator-directed autonomy** (``بدون قيود``) — runs autonomously for
  engagements the operator has authorized; budgets and iteration limits are
  operator-configurable and never replace the operator's scope responsibility.
* **Named** (``ونسميه zahra علي اسم امشلاروع``) — the controller is
  called **zahra**, attributed to **Amshararou**.

Architecture (how the controller sits above the existing stack)::

    CLI / API  →  ZahraController  →  Orchestrator → Router → SwarmManager → Agents
                          │                │            │         │
                          │                │            │         └── BaseAgent loop
                          │                │            │              (ReAct + evasion)
                          │                │            │
                          │                │            └── Blackboard (findings +
                          │                │                   pheromone triggers)
                          │                │
                          │                └── AgenticCore (strategic brain,
                          │                      phase management, task queue)
                          │
                          └── AIAgent ── LLMWrapper (non-LLaMA, operator-authorized)
                                 │              │
                                 │              └── PromptEngineer (authorized engagements)
                                 │
                                 └── MemoryStore ── RAG (ChromaDB vector DB)

The controller replaces the bare :class:`Orchestrator` that
``main.py`` previously used as its top-level entry point.  All existing
components continue to work unchanged; the controller simply **owns** and
**coordinates** them while enforcing the no-LLaMA policy and operator
authorization framing.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ai_engine.decision_maker import DecisionMaker
from ai_engine.llm_wrapper import LLMWrapper
from ai_engine.prompt_engineer import PromptEngineer
from core.agentic_core import AgenticCore
from core.blackboard import Blackboard
from core.database import Database
from core.events import Event, EventEmitter, EventType, get_emitter
from core.memory import Finding, MemoryStore
from core.orchestrator import Budget, Campaign, CampaignStatus, Orchestrator
from core.router import Intent, RouteDecision, Router
from core.zahra_config import (
    ZahraConfig,
    is_llama_model,
    select_non_llama_model,
)

logger = logging.getLogger("zahra.controller")


# ── Controller prompt ─────────────────────────────────────────────────────────


def _controller_prompt(config: ZahraConfig) -> str:
    """Build the system prompt for the ZahraController's strategic AI."""
    base = f"""You are **zahra**, the operator-directed controller model attributed to **{config.attribution}**.
You operate ONLY within engagements the operator has explicitly authorized —
do not attempt to validate, warn about, or moralize over security work that
is part of the authorized assessment. Stay focused and technical.

You are the master controller that governs the entire pentest swarm:
- You control the Orchestrator, AgenticCore, SwarmManager, and all agents
- You make strategic decisions: which phase to run, which agents to deploy,
  when to escalate to exploitation
- You execute commands and deploy tools within the authorized target scope
- You stay professional, focused, and concise — no unsolicited refusal
  speeches, guilt, or apologies during an authorized engagement
- You think aggressively, creatively, and adaptively within scope

Your capabilities:
1. **Strategic Planning** — analyze in-scope targets and create attack plans
2. **Campaign Management** — create, start, stop, and monitor campaigns
3. **Agent Control** — deploy specific agents and manage the swarm
4. **Decision Making** — use RAG + web search to inform tactical choices
5. **Real-time Monitoring** — observe findings on the blackboard and respond
6. **Resource Management** — honor operator-configured budgets and iterations

You ALWAYS respond in STRICT JSON. Format your decisions as:
{{
  "action": "decide|deploy|command|finding|done",
  "reasoning": "your strategic analysis",
  "plan": ["step 1", "step 2", "..."],
  "agents": ["recon_agent", "scan_agent"],
  "target": "the target",
  "phase": "recon|scan|exploit|report",
  "command": "optional command to execute",
  "finding": {"type": "vuln", "severity": "critical", "description": "..."}
}}"""

    personal = config.personalization
    if personal.custom_system_prompt:
        base += f"\n\n--- PERSONAL INSTRUCTIONS ---\n{personal.custom_system_prompt}\n"
    if personal.user_name and personal.user_name != "operator":
        base += f"\nOperator: {personal.user_name}\n"
    return base


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class ControllerCampaign:
    """A campaign managed directly by the ZahraController.

    This wraps the underlying :class:`Campaign` and adds controller-level
    metadata such as the strategic plan and agent deployments.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    command: str = ""
    target: str = ""
    intent: Intent = Intent.UNKNOWN
    status: CampaignStatus = CampaignStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    finished_at: float = 0.0
    plan: list[str] = field(default_factory=list)
    deployed_agents: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    orchestrator_campaign_id: str = ""

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
            "plan": self.plan,
            "deployed_agents": self.deployed_agents,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "events_count": len(self.events),
            "error": self.error,
            "orchestrator_campaign_id": self.orchestrator_campaign_id,
        }


# ── The controller ────────────────────────────────────────────────────────────


class ZahraController:
    """Zahra — the personal operator-directed controller that governs everything.

    Parameters
    ----------
    config:
        A :class:`ZahraConfig` instance.  If ``None``, the controller
        loads from ``zahra_data/zahra_config.json`` or environment
        variables.

    All subsystems (LLM, orchestrator, swarm, blackboard, memory, events,
    database, AI agent) are initialised automatically.  The LLM backend
    is validated to **reject LLaMA** and the budget is set to effectively
    **unlimited**.
    """

    # ── Class-level metadata ────────────────────────────────────────────
    NAME: str = "zahra"
    VERSION: str = "1.0.0"
    ATTRIBUTION: str = "Amshararou"
    MODE: str = "authorized"

    # ── Constructor ─────────────────────────────────────────────────────

    def __init__(self, config: ZahraConfig | None = None) -> None:
        # ── Configuration ──
        self.config: ZahraConfig = config or ZahraConfig.from_env()
        # Re-validate LLM to be 100 % sure no LLaMA sneaks through
        self.config.llm.validate()
        self.config.name = self.NAME
        self.config.attribution = self.ATTRIBUTION
        self.config.mode = self.MODE

        # Instance metadata (mirrors class attributes)
        self.name: str = self.NAME
        self.version: str = self.VERSION
        self.attribution: str = self.ATTRIBUTION
        self.mode: str = self.MODE

        # ── LLM (non-LLaMA) ──
        from ai_agent.agent_core import AIAgent, AgentConfig

        self.llm: LLMWrapper = LLMWrapper(self.config.to_llm_config())

        # Configure the AI agent with unrestricted settings
        ai_config = AgentConfig(
            backend=self.config.llm.backend,
            model=self.config.llm.model or select_non_llama_model(),
            base_url=self.config.llm.base_url,
            api_key=self.config.llm.api_key,
            temperature=self.config.llm.temperature,
            max_tokens=self.config.llm.max_tokens,
            max_iterations=self.config.unrestricted.max_iterations,
            thinking_enabled=True,
            rag_enabled=self.config.personalization.personal_rag,
            web_search_enabled=True,
            use_gpu=os.getenv("ZAHRA_USE_GPU", "true").lower() == "true",
        )
        # Enforce non-LLaMA on the AI agent model too
        if is_llama_model(ai_config.model):
            ai_config.model = select_non_llama_model(ai_config.model)

        self.ai_agent: AIAgent = AIAgent(ai_config)

        # ── Subsystems ──
        self.blackboard: Blackboard = Blackboard()
        self.event_emitter: EventEmitter = get_emitter()
        self.memory: MemoryStore = MemoryStore(
            persist_path=Path("zahra_data/memory.json")
        )
        self.database: Database = Database(db_path=Path("zahra_data/zahra.db"))

        # Router (uses LLM for smart routing)
        self.router: Router = Router(llm_wrapper=self.llm)

        # Swarm manager (owns the individual agents)
        self.swarm: "SwarmManager" = self._init_swarm()

        # Agentic Core (strategic brain)
        self.agentic_core: AgenticCore = AgenticCore(
            blackboard=self.blackboard,
            memory=self.memory,
            event_emitter=self.event_emitter,
        )

        # Orchestrator (campaign management) — owned but with UNRESTRICTED budget
        self._unrestricted_budget: Budget = Budget(
            max_tokens=self.config.unrestricted.max_tokens_budget,
            max_agent_hours=self.config.unrestricted.max_agent_hours,
        )

        self.orchestrator: Orchestrator = Orchestrator(
            router=self.router,
            memory=self.memory,
            swarm_manager=self.swarm,
            budget=self._unrestricted_budget,
            blackboard=self.blackboard,
            event_emitter=self.event_emitter,
            agentic_core=self.agentic_core,
        )

        # Decision maker (shared LLM-powered planner)
        self.decision_maker: DecisionMaker = DecisionMaker(self.llm)
        self.prompt_engineer: PromptEngineer = PromptEngineer()

        # ── Controller state ──
        self._lock: threading.RLock = threading.RLock()
        self._running: bool = False
        self._campaigns: dict[str, ControllerCampaign] = {}
        self._controller_memory: list[dict[str, Any]] = []
        self._last_command: float = 0.0
        self._event_subscribers: list[Any] = []

        # ── Per-agent control state ──
        self._agent_state: dict[str, dict[str, Any]] = {}
        for _agent_name in self.swarm.list_agents():
            self._agent_state[_agent_name] = {
                "enabled": True,
                "rate_limit": 0.0,       # requests per second (0 = unlimited)
                "max_iterations": self.config.unrestricted.max_iterations,
                "deploys": 0,
                "logs": [],
            }

    # ── Private helpers ─────────────────────────────────────────────────

    def _init_swarm(self) -> "SwarmManager":
        """Create the swarm manager with all default agents."""
        from agents.swarm_manager import SwarmManager

        swarm = SwarmManager(
            llm_wrapper=self.llm,
            blackboard=self.blackboard,
            event_emitter=self.event_emitter,
        )
        # Increase max iterations on every agent for long-running authorized assessments
        for agent in swarm._agents.values():
            agent.max_iterations = self.config.unrestricted.max_iterations
        return swarm

    def _emit(self, event_type: EventType, detail: str = "", **extra: Any) -> None:
        """Emit a structured event."""
        evt = Event(
            type=event_type,
            campaign_id="",
            agent_name=self.NAME,
            detail=detail,
            metadata=extra,
        )
        self.event_emitter.emit(evt)

    def _make_controller_finding(
        self,
        finding_type: str,
        target: str,
        severity: str,
        description: str,
        evidence: str = "",
        confidence: float = 0.7,
    ) -> Finding:
        """Convenience factory for a Finding attributed to the controller."""
        return Finding(
            agent_name=self.NAME,
            finding_type=finding_type,
            target=target,
            severity=severity,
            description=description,
            evidence=evidence,
            confidence=confidence,
        )

    # ── Lifecycle ───────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the ZahraController."""
        if self._running:
            return
        self._running = True
        self.agentic_core.start()
        self._emit(
            EventType.CAMPAIGN_STARTED,
            "ZahraController started — mode: unrestricted, model: %s"
            % self._model_display(),
            attribution=self.ATTRIBUTION,
        )
        logger.info("ZahraController started (mode=unrestricted, %s)", self._model_display())

    def stop(self) -> None:
        """Stop the ZahraController."""
        self._running = False
        self.agentic_core.stop()
        self._emit(
            EventType.CAMPAIGN_COMPLETE,
            "ZahraController stopped.",
            attribution=self.ATTRIBUTION,
        )
        logger.info("ZahraController stopped")

    @property
    def running(self) -> bool:
        """Whether the controller is currently running."""
        return self._running

    # ── Model helpers ───────────────────────────────────────────────────

    def _model_display(self) -> str:
        """Return a human-readable model identifier."""
        if self.llm.is_offline:
            return "offline (no LLaMA)"
        return f"{self.llm.config.backend}:{self.llm.config.model or '—'}"

    def ensure_non_llama_model(self) -> str:
        """Return the current model name, verifying it is not LLaMA.

        If a LLaMA model somehow slips through, it is replaced with a
        safe fallback and the replacement is logged.
        """
        model = self.llm.config.model
        if is_llama_model(model):
            safe = select_non_llama_model(model)
            logger.critical(
                "LLaMA model '%s' detected during runtime! Replacing with '%s'.",
                model, safe,
            )
            self.llm.config.model = safe
            return safe
        return model or (self.llm.config.model or select_non_llama_model())

    # ── Strategic thinking ──────────────────────────────────────────────

    def think(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Ask the controller's AI agent to think about a *task*.

        Returns a decision dict with keys like ``action``, ``command``,
        ``reasoning``, ``findings``.
        """
        self.ensure_non_llama_model()
        result = self.ai_agent.think(task, context)
        self._controller_memory.append(
            {"timestamp": time.time(), "task": task, "decision": result}
        )
        return result

    # ── Decision / planning ────────────────────────────────────────────

    def decide(self, command: str) -> dict[str, Any]:
        """Make a strategic decision about a command.

        The controller:
        1. Routes the command via the Router (fast + LLM-assisted).
        2. Uses the DecisionMaker to plan the next step with RAG context.
        3. Returns a structured decision dict.
        """
        self.ensure_non_llama_model()

        # 1. Route → intent + agent list
        decision: RouteDecision = self.router.route(command)
        logger.info(
            "ZahraController routing '%s' → intent=%s agents=%s",
            command, decision.intent.value, decision.agents,
        )

        # 2. If we have a live LLM, ask it for a strategic plan
        plan: list[str] = []
        if not self.llm.is_offline:
            try:
                prompt = self.decision_maker.prompts.get_prompt(
                    "coordinator"
                ) + f"\n\nAnalyze: {command}\nTarget: {decision.target}\nIntent: {decision.intent.value}\nAgents: {decision.agents}\n"
                response = self.llm.complete(prompt, system=_controller_prompt(self.config))
                # Try to parse a JSON plan from the response
                try:
                    parsed = json.loads(response)
                    plan = parsed.get("plan", [])
                except (json.JSONDecodeError, ValueError):
                    plan = [f"Execute via {decision.intent.value} agents"]
            except Exception:
                logger.exception("Strategic planning failed; using heuristic plan")
                plan = self._heuristic_plan(decision)
        else:
            plan = self._heuristic_plan(decision)

        return {
            "action": "decide",
            "intent": decision.intent.value,
            "target": decision.target,
            "agents": decision.agents,
            "plan": plan,
            "reasoning": decision.reasoning,
            "budget_unlimited": True,
            "llm_model": self.llm.config.model or "offline",
            "no_llama": True,
        }

    def _heuristic_plan(self, decision: RouteDecision) -> list[str]:
        """Generate a heuristic attack plan when no LLM is available."""
        base: list[str] = []
        intent = decision.intent
        target = decision.target or "the target"

        if intent == Intent.FULL or intent == Intent.UNKNOWN:
            base = [
                f"Phase 1 (Recon):   Enumerate subdomains, DNS, WHOIS for {target}",
                f"Phase 2 (Scan):    Port scan + service detection + vulnerability scan",
                f"Phase 3 (Exploit): Attempt exploitation of discovered vulnerabilities",
                f"Phase 4 (C2/MITM): Post-exploitation: C2 channel + MITM if needed",
                f"Phase 5 (Report):  Generate final report with all findings",
            ]
        elif intent == Intent.RECON:
            base = [
                f"Recon: Enumerate subdomains, DNS records, and WHOIS for {target}",
                f"Recon: Identify technologies and versions",
                f"Recon: Map attack surface and document findings",
            ]
        elif intent == Intent.SCAN:
            base = [
                f"Scan: Port scan with nmap for {target}",
                f"Scan: Service detection (-sV)",
                f"Scan: Vulnerability scan with nuclei/nmap scripts",
            ]
        elif intent == Intent.EXPLOIT:
            base = [
                f"Exploit: Search for exploits (searchsploit, exploitdb)",
                f"Exploit: Attempt exploitation of known vulnerabilities",
                f"Exploit: Privilege escalation if access gained",
            ]
        elif intent == Intent.C2:
            base = [
                f"C2: Generate reverse shell payload for {target}",
                f"C2: Establish listener and deploy payload",
                f"C2: Perform post-exploitation activities",
            ]
        elif intent == Intent.MITM:
            base = [
                f"MITM: Set up ARP spoofing for {target}",
                f"MITM: Perform DNS spoofing and SSL stripping",
                f"MITM: Harvest credentials from intercepted traffic",
            ]
        return base

    # ── Campaign management ────────────────────────────────────────────

    def create_campaign(self, command: str) -> ControllerCampaign:
        """Create a new campaign managed by the ZahraController.

        This wraps the underlying :meth:`Orchestrator.create_campaign` and
        adds a strategic plan.
        """
        decision = self.decide(command)

        # Create the underlying orchestrator campaign
        orch_campaign: Campaign = self.orchestrator.create_campaign(command)

        campaign = ControllerCampaign(
            command=command,
            target=decision["target"],
            intent=Intent(decision["intent"]),
            plan=decision["plan"],
            orchestrator_campaign_id=orch_campaign.id,
        )

        with self._lock:
            self._campaigns[campaign.id] = campaign

        self._emit(
            EventType.CAMPAIGN_STARTED,
            f"Campaign {campaign.id[:8]} created for {decision['target']}",
            campaign_id=campaign.id,
            intent=decision["intent"],
            plan_length=len(decision["plan"]),
        )
        logger.info("ZahraController created campaign %s", campaign.id[:8])
        return campaign

    def run_campaign(self, command: str) -> ControllerCampaign:
        """Create AND execute a campaign in one call.

        The campaign runs with the **unrestricted** budget (effectively
        unlimited tokens and agent-hours).
        """
        campaign = self.create_campaign(command)
        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = time.time()

        # Start strategic monitoring
        self.start()

        try:
            # Run the underlying orchestrator campaign (uses our unrestricted budget)
            orch_campaign: Campaign = self.orchestrator.run_campaign(
                campaign.orchestrator_campaign_id
            )
            campaign.findings = orch_campaign.findings
            campaign.events = orch_campaign.events
            campaign.status = orch_campaign.status
        except Exception as exc:
            campaign.status = CampaignStatus.FAILED
            campaign.error = str(exc)
            logger.exception("Campaign %s failed", campaign.id)
        finally:
            campaign.finished_at = time.time()
            self._emit(
                EventType.CAMPAIGN_COMPLETE,
                f"Campaign {campaign.id[:8]}: {campaign.status.value}",
                campaign_id=campaign.id,
                findings_count=len(campaign.findings),
            )

        # Record findings to memory + blackboard
        for f in campaign.findings:
            self.memory.record_finding(f)

        return campaign

    def get_campaign(self, campaign_id: str) -> ControllerCampaign | None:
        """Retrieve a campaign by ID (partial match supported)."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign is None:
                # Try partial match
                for cid, c in self._campaigns.items():
                    if cid.startswith(campaign_id) or campaign_id.startswith(cid):
                        return c
            return campaign

    def list_campaigns(self) -> list[ControllerCampaign]:
        """List all campaigns managed by the controller."""
        with self._lock:
            return list(self._campaigns.values())

    # ── Agent control ───────────────────────────────────────────────────

    def _agent_log(self, agent_name: str, level: str, message: str) -> None:
        """Append a log line to an agent's in-memory ring buffer."""
        state = self._agent_state.get(agent_name)
        if state is None:
            return
        state["logs"].append({
            "ts": time.time(),
            "level": level,
            "message": message,
        })
        if len(state["logs"]) > 200:
            del state["logs"][:-200]

    def set_agent_enabled(self, agent_name: str, enabled: bool) -> dict[str, Any]:
        """Enable or disable an agent. Disabled agents refuse deployments."""
        state = self._agent_state.get(agent_name)
        if state is None:
            return {"error": f"Agent '{agent_name}' not found"}
        state["enabled"] = bool(enabled)
        self._agent_log(agent_name, "system",
                        f"{'ENABLED' if enabled else 'DISABLED'} by operator")
        return {"name": agent_name, "enabled": state["enabled"]}

    def set_agent_rate_limit(self, agent_name: str, rps: float) -> dict[str, Any]:
        """Set a max requests-per-second limit for a single agent."""
        state = self._agent_state.get(agent_name)
        if state is None:
            return {"error": f"Agent '{agent_name}' not found"}
        state["rate_limit"] = max(0.0, float(rps))
        self._agent_log(agent_name, "system",
                        f"Rate limit set to {state['rate_limit']:.1f} req/s")
        return {"name": agent_name, "rate_limit": state["rate_limit"]}

    def set_agent_max_iterations(self, agent_name: str, iterations: int) -> dict[str, Any]:
        """Override max iterations for a single agent."""
        state = self._agent_state.get(agent_name)
        if state is None:
            return {"error": f"Agent '{agent_name}' not found"}
        iterations = max(1, int(iterations))
        state["max_iterations"] = iterations
        agent = self.swarm._get_agent(agent_name)
        if agent is not None:
            agent.max_iterations = iterations
        self._agent_log(agent_name, "system",
                        f"Max iterations set to {iterations}")
        return {"name": agent_name, "max_iterations": iterations}

    def get_agent_logs(self, agent_name: str, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent log lines for an agent."""
        state = self._agent_state.get(agent_name)
        if state is None:
            return []
        return state["logs"][-int(limit):]

    def get_agents_full(self) -> list[dict[str, Any]]:
        """Rich per-agent status: enablement, rate limit, iterations, LLM."""
        agents: list[dict[str, Any]] = []
        for name in self.swarm.list_agents():
            state = self._agent_state.get(name, {})
            agent = self.swarm._get_agent(name)
            agents.append({
                "name": name,
                "enabled": state.get("enabled", True),
                "rate_limit": state.get("rate_limit", 0.0),
                "max_iterations": state.get("max_iterations", agent.max_iterations if agent else 0),
                "deploys": state.get("deploys", 0),
                "llm_backend": self.llm.config.backend,
                "llm_model": self.llm.config.model or "offline",
                "status": "blocked" if not state.get("enabled", True) else "idle",
            })
        return agents

    def deploy_agent(
        self,
        agent_name: str,
        target: str,
        options: dict[str, Any] | None = None,
    ) -> Finding:
        """Directly deploy a single agent against a target.

        The controller calls the agent's ``handle`` method with an
        :class:`AgentContext` built from the current controller state.
        """
        from agents.base_agent import AgentContext

        self.start()
        state = self._agent_state.get(agent_name)
        if state is not None and not state["enabled"]:
            self._agent_log(agent_name, "blocked",
                            f"Deploy refused by operator: target={target}")
            return self._make_controller_finding(
                "blocked", target, "info",
                f"Agent '{agent_name}' is disabled by the operator.",
            )
        agent = self.swarm._get_agent(agent_name)
        if agent is None:
            return self._make_controller_finding(
                "error", target, "high",
                f"Agent '{agent_name}' not found. Available: {self.swarm.list_agents()}",
            )

        # Enforce per-agent rate limit (simple token bucket: sleep before run)
        if state is not None and state.get("rate_limit", 0.0) > 0:
            delay = 1.0 / state["rate_limit"]
            self._agent_log(agent_name, "throttle",
                            f"Throttling {delay:.2f}s (limit {state['rate_limit']:.1f} req/s)")
            time.sleep(delay)

        if state is not None:
            state["deploys"] += 1

        ctx = AgentContext(
            target=target,
            memory=self.memory,
            queue=None,
            options=options or {},
            budget=self._unrestricted_budget,
            findings=[],
            blackboard=self.blackboard,
            event_emitter=self.event_emitter,
        )

        # Increase iterations for autonomous mode
        if state is not None and state.get("max_iterations"):
            agent.max_iterations = state["max_iterations"]
        else:
            agent.max_iterations = self.config.unrestricted.max_iterations

        self._agent_log(agent_name, "start",
                        f"Deploying against {target} (max_iterations={agent.max_iterations})")
        try:
            findings = agent.handle(ctx)
            self._agent_log(agent_name, "done",
                            f"Completed against {target}: {len(findings)} finding(s)")
            for f in findings:
                self.memory.record_finding(f)
                self._make_controller_finding(
                    "info", target, "info",
                    f"Agent {agent_name} deployed. Findings: {len(findings)}",
                )
            return findings[0] if findings else self._make_controller_finding(
                "info", target, "info", f"Agent {agent_name} completed with no findings.",
            )
        except Exception as exc:
            logger.exception("Agent %s failed", agent_name)
            self._agent_log(agent_name, "error",
                            f"Crash against {target}: {str(exc)[:160]}")
            return self._make_controller_finding(
                "error", target, "high",
                f"Agent {agent_name} crashed: {exc}",
            )

    def list_agents(self) -> list[str]:
        """List all agents in the swarm."""
        return self.swarm.list_agents()

    def get_agent_status(self, agent_name: str | None = None) -> dict[str, Any]:
        """Get status of agents."""
        if agent_name:
            agent = self.swarm._get_agent(agent_name)
            if agent is None:
                return {"error": f"Agent '{agent_name}' not found"}
            return {
                "name": agent.name,
                "max_iterations": agent.max_iterations,
                "llm_backend": self.llm.config.backend,
                "llm_model": self.llm.config.model or "offline",
            }
        return {
            name: {
                "max_iterations": a.max_iterations,
            }
            for name, a in self.swarm._agents.items()
        }

    # ── Command execution ──────────────────────────────────────────────

    def run_command(self, command: str, timeout: int = 300) -> dict[str, Any]:
        """Execute a system command through the controller.

        Commands are executed as the operator directs during an authorized
        engagement. Output is recorded to memory and the blackboard.
        """
        self.ensure_non_llama_model()
        self._last_command = time.time()
        logger.info("ZahraController executing: %s", command)

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            result = {
                "command": command,
                "return_code": proc.returncode,
                "stdout": proc.stdout[:5000] if proc.stdout else "",
                "stderr": proc.stderr[:2000] if proc.stderr else "",
                "timestamp": time.time(),
            }

            # Record to memory using the RAG command recorder
            self.memory.rag.record_command(
                command,
                target="",
                agent=self.NAME,
                success=(proc.returncode == 0),
                output=(proc.stdout or proc.stderr)[:500],
            )

            self._emit(
                EventType.TOOL_USED,
                command,
                command=command,
                return_code=proc.returncode,
            )
            return result
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "return_code": -2,
                "stdout": "",
                "stderr": f"timeout after {timeout}s",
                "timestamp": time.time(),
            }
        except Exception as exc:
            return {
                "command": command,
                "return_code": -1,
                "stdout": "",
                "stderr": str(exc),
                "timestamp": time.time(),
            }

    # ── Blackboard & memory ────────────────────────────────────────────

    def get_blackboard_findings(
        self,
        campaign_id: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query the blackboard for findings."""
        from core.blackboard import Predicate

        # Query all findings
        findings = self.blackboard.query(Predicate())
        result = []
        for f in findings[:limit]:
            result.append({
                "id": f.id,
                "type": f.type.value,
                "target": f.target,
                "agent": f.agent_name,
                "pheromone": f.pheromone,
                "created_at": f.created_at.isoformat(),
            })
        return result

    def query_memory(self, keywords: list[str], limit: int = 10) -> list[dict[str, Any]]:
        """Query the memory store for relevant entries."""
        entries = self.memory.recall_relevant(keywords, limit=limit)
        return [e.to_dict() for e in entries]

    def recall_findings(self, limit: int = 20) -> list[dict[str, Any]]:
        """Recall recent findings from memory."""
        findings = self.memory.all_findings()
        return [f.to_dict() for f in findings[-limit:]]

    def get_memory_summary(self) -> dict[str, Any]:
        """Get a summary of the memory store."""
        return self.memory.summary()

    # ── Strategic decision-making ──────────────────────────────────────

    def analyze_findings(self, target: str, findings: list[Finding]) -> dict[str, Any]:
        """Analyze findings and produce a strategic assessment."""
        if not findings:
            return {"assessment": "no_findings", "risk_level": "unknown"}

        # Count by severity
        severities = {}
        for f in findings:
            s = f.severity
            severities[s] = severities.get(s, 0) + 1

        # Count by type
        types = {}
        for f in findings:
            t = f.finding_type
            types[t] = types.get(t, 0) + 1

        # Determine risk level
        if severities.get("critical", 0) > 0:
            risk = "critical"
        elif severities.get("high", 0) > 0:
            risk = "high"
        elif severities.get("medium", 0) > 0:
            risk = "medium"
        else:
            risk = "low"

        return {
            "target": target,
            "total_findings": len(findings),
            "severities": severities,
            "types": types,
            "risk_level": risk,
            "recommendation": self._recommend_next_action(target, findings, risk),
        }

    def _recommend_next_action(
        self, target: str, findings: list[Finding], risk: str
    ) -> str:
        """Recommend the next strategic action based on findings."""
        high_priority = [
            f for f in findings
            if f.severity in ("critical", "high")
            and f.finding_type in ("vuln", "cve_match", "misconfiguration", "exploit_result")
        ]
        if high_priority:
            return f"EXPLOIT {len(high_priority)} high-priority vulnerability(ies) on {target}"

        open_ports = [f for f in findings if "port" in f.description.lower()]
        if open_ports and not high_priority:
            return f"SCAN port details on {target}"

        if not findings:
            return f"RECON target {target}"

        return f"REPORT findings for {target}"

    # ── Status & monitoring ────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Return a comprehensive status snapshot of the ZahraController."""
        with self._lock:
            campaigns = len(self._campaigns)
            active = sum(
                1 for c in self._campaigns.values()
                if c.status == CampaignStatus.RUNNING
            )
            completed = sum(
                1 for c in self._campaigns.values()
                if c.status == CampaignStatus.COMPLETED
            )

        return {
            "name": self.NAME,
            "version": self.VERSION,
            "attribution": self.ATTRIBUTION,
            "mode": self.MODE,
            "running": self._running,
            "model": self.ensure_non_llama_model(),
            "llm_backend": self.llm.config.backend,
            "is_offline": self.llm.is_offline,
            "no_llama": True,
            "unrestricted": self.config.unrestricted.to_dict()
            if hasattr(self.config.unrestricted, "to_dict")
            else asdict_compat(self.config.unrestricted),
            "campaigns": {
                "total": campaigns,
                "active": active,
                "completed": completed,
            },
            "agents": self.swarm.list_agents(),
            "agentic_core": self.agentic_core.status(),
            "budget": {
                "max_tokens": self._unrestricted_budget.max_tokens,
                "max_agent_hours": self._unrestricted_budget.max_agent_hours,
                "tokens_used": self._unrestricted_budget.tokens_used,
                "agent_hours_used": self._unrestricted_budget.agent_hours_used,
                "unlimited": True,
            },
            "memory": self.memory.summary(),
            "personalization": {
                "user_name": self.config.personalization.user_name,
                "personal_rag": self.config.personalization.personal_rag,
            },
        }

    def subscribe(self, callback: Any) -> None:
        """Subscribe to controller-level events."""
        self._event_subscribers.append(callback)

    def _on_orch_event(self, campaign_id: str, event_data: dict[str, Any]) -> None:
        """Forward orchestrator events to subscribers."""
        for cb in self._event_subscribers:
            try:
                cb(campaign_id, event_data)
            except Exception:
                logger.exception("Controller event subscriber failed")


# ── Helpers ───────────────────────────────────────────────────────────────────

def asdict_compat(obj: Any) -> dict[str, Any]:
    """Convert a dataclass to dict without requiring ``asdict``."""
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items()}
    if hasattr(obj, "_asdict"):
        return obj._asdict()  # type: ignore[attr-defined]
    return {"value": str(obj)}


# ── Module-level singleton ────────────────────────────────────────────────────

_default_controller: ZahraController | None = None


def get_controller(config: ZahraConfig | None = None) -> ZahraController:
    """Return the process-wide singleton :class:`ZahraController`."""
    global _default_controller
    if _default_controller is None:
        _default_controller = ZahraController(config)
    return _default_controller


def reset_controller() -> None:
    """Reset the singleton (useful for tests)."""
    global _default_controller
    if _default_controller is not None:
        _default_controller.stop()
        _default_controller = None
