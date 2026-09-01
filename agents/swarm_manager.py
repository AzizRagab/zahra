"""Swarm manager — coordinates the LLM-driven agent swarm (async).

The swarm manager:
1. Creates and registers the three agents (Recon, Scan, Exploit)
2. Passes the LLM wrapper to each agent
3. Executes them **concurrently** using asyncio + a stigmergic
   :class:`MemoryQueue` (blackboard)
4. Recon publishes findings to the queue as it discovers them
5. Scan / Exploit subscribe to the queue and react **immediately** —
   e.g. the scan agent starts scanning port 80 the moment recon
   publishes it, without waiting for recon to finish all ports
6. Enforces budget caps and emits events

This makes the swarm a true asynchronous system instead of a
sequential pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Callable

from agents.base_agent import AgentContext, BaseAgent
from agents.c2_agent import C2Agent
from agents.exploit_agent import ExploitAgent
from agents.lateral_agent import LateralAgent
from agents.mitm_agent import MITMAgent
from agents.recon_agent import ReconAgent
from agents.scan_agent import ScanAgent
from core.blackboard import Blackboard
from core.events import Event, EventEmitter, EventType, get_emitter
from core.memory import Finding, MemoryQueue, MemoryStore
from core.orchestrator import Budget, Campaign
from core.router import RouteDecision

logger = logging.getLogger("zahra.agents.swarm")


class SwarmManager:
    """Coordinates the execution of LLM-driven agents in the zahra swarm."""

    def __init__(
        self,
        *,
        llm_wrapper: Any | None = None,
        agents: list[BaseAgent] | None = None,
        max_workers: int = 4,
        blackboard: Blackboard | None = None,
        event_emitter: EventEmitter | None = None,
    ) -> None:
        self._llm = llm_wrapper
        self._agents: dict[str, BaseAgent] = {}
        self._max_workers = max_workers
        self._lock = threading.RLock()
        self._event_callbacks: list[Callable[[dict[str, Any]], None]] = []
        self.blackboard = blackboard or Blackboard()
        self.event_emitter = event_emitter or get_emitter()

        # Register default agents if none provided.
        if agents is None:
            agents = [
                ReconAgent(llm_wrapper=llm_wrapper),
                ScanAgent(llm_wrapper=llm_wrapper),
                ExploitAgent(llm_wrapper=llm_wrapper),
                LateralAgent(llm_wrapper=llm_wrapper),
                C2Agent(llm_wrapper=llm_wrapper),
                MITMAgent(llm_wrapper=llm_wrapper),
            ]
        for agent in agents:
            self.register(agent)

    # -- registration ------------------------------------------------------

    def register(self, agent: BaseAgent) -> None:
        """Add an agent to the swarm."""
        with self._lock:
            self._agents[agent.name] = agent
        logger.info("registered agent: %s", agent.name)

    def unregister(self, name: str) -> BaseAgent | None:
        with self._lock:
            return self._agents.pop(name, None)

    def list_agents(self) -> list[str]:
        with self._lock:
            return list(self._agents.keys())

    # -- event subscription ------------------------------------------------

    def on_event(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self._event_callbacks.append(callback)

    def _emit(self, event: dict[str, Any]) -> None:
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception:
                logger.exception("event callback failed")

    # -- synchronous entry point (backward compatible) ---------------------

    def execute(
        self,
        campaign: Campaign,
        decision: RouteDecision,
        memory: MemoryStore,
        budget: Budget,
    ) -> list[Finding]:
        """Execute the swarm for a campaign (synchronous wrapper).

        This runs the async swarm to completion and returns all findings.
        """
        return asyncio.run(
            self.execute_async(campaign, decision, memory, budget)
        )

    # -- async execution ---------------------------------------------------

    async def execute_async(
        self,
        campaign: Campaign,
        decision: RouteDecision,
        memory: MemoryStore,
        budget: Budget,
    ) -> list[Finding]:
        """Execute the swarm concurrently using asyncio + MemoryQueue.

        Pipeline:
        1. Create a shared :class:`MemoryQueue` (stigmergic blackboard).
        2. Start the recon agent as a task — it publishes findings to the
           queue as it discovers them.
        3. Start the scan agent as a background task that subscribes to the
           queue and reacts to open ports immediately.
        4. Start the exploit agent as a background task that subscribes to
           the queue and reacts to vulnerabilities immediately.
        5. Wait for recon to finish, close the queue, then wait for the
           scan / exploit tasks to drain and finish.
        """
        all_findings: list[Finding] = []
        agent_names = decision.agents or ["recon_agent", "scan_agent", "exploit_agent"]
        
        # Emit campaign started event
        self._emit_event(EventType.CAMPAIGN_STARTED, campaign.id, detail=f"Agents: {', '.join(agent_names)}")

        logger.info(
            "swarm executing campaign %s with agents: %s (async)",
            campaign.id,
            ", ".join(agent_names),
        )

        # Shared stigmergic blackboard.
        queue = MemoryQueue()

        # Track processed finding IDs to avoid duplicate reactions.
        processed: set[str] = set()

        # Build the base context (shared by all agents).
        def make_ctx(agent_name: str, findings: list[Finding] | None = None) -> AgentContext:
            return AgentContext(
                target=campaign.target,
                memory=memory,
                queue=queue,
                options=decision.options,
                budget=budget,
                findings=findings or list(all_findings),
            )

        # -- agent runners -------------------------------------------------

        async def run_recon() -> list[Finding]:
            """Run recon to completion, publishing findings as it goes."""
            if "recon_agent" not in agent_names:
                return []
            agent = self._get_agent("recon_agent")
            if agent is None:
                logger.warning("recon_agent not registered, skipping")
                return []
            if budget.exceeded():
                logger.warning("budget exceeded before recon")
                return []

            # Emit event
            self._emit_event(EventType.AGENT_STARTED, campaign.id, detail="recon_agent starting")
            
            self._emit({
                "type": "agent_started",
                "campaign_id": campaign.id,
                "agent": "recon_agent",
                "target": campaign.target,
                "timestamp": time.time(),
            })
            start = time.time()
            try:
                # Run the blocking agent loop in a thread so the event loop
                # stays free for the queue subscribers.
                findings = await asyncio.to_thread(
                    agent.handle, make_ctx("recon_agent")
                )
                
                # Write findings to blackboard
                for f in findings:
                    self._write_to_blackboard(campaign.id, "recon_agent", f)
                
                self._emit({
                    "type": "agent_finished",
                    "campaign_id": campaign.id,
                    "agent": "recon_agent",
                    "findings": len(findings),
                    "duration": time.time() - start,
                    "timestamp": time.time(),
                })
                self._emit_event(EventType.AGENT_FINISHED, campaign.id, detail=f"recon_agent: {len(findings)} findings")
                logger.info(
                    "recon_agent finished: %d findings in %.2fs",
                    len(findings),
                    time.time() - start,
                )
                return findings
            except Exception as exc:
                logger.exception("recon_agent failed")
                error_finding = Finding(
                    agent_name="recon_agent",
                    finding_type="error",
                    target=campaign.target,
                    severity="medium",
                    description=f"Recon agent crashed: {exc}",
                    confidence=1.0,
                )
                self._emit({
                    "type": "agent_error",
                    "campaign_id": campaign.id,
                    "agent": "recon_agent",
                    "error": str(exc),
                    "timestamp": time.time(),
                })
                self._emit_event(EventType.AGENT_ERROR, campaign.id, detail=f"recon_agent failed: {exc}")
                return [error_finding]

        async def run_scan() -> list[Finding]:
            """Scan the target.

            If scan is the primary agent (no recon in the pipeline), it runs
            directly against the target. Otherwise it subscribes to the queue
            and reacts to open ports immediately as recon publishes them.
            """
            agent = self._get_agent("scan_agent")
            if agent is None:
                logger.warning("scan_agent not registered, skipping")
                return []
            if "scan_agent" not in agent_names:
                return []

            self._emit({
                "type": "agent_started",
                "campaign_id": campaign.id,
                "agent": "scan_agent",
                "target": campaign.target,
                "timestamp": time.time(),
            })
            start = time.time()
            findings: list[Finding] = []

            # If scan is the primary agent (no recon producing findings),
            # run it directly against the target.
            if "recon_agent" not in agent_names:
                ctx = make_ctx("scan_agent")
                try:
                    agent_findings = await asyncio.to_thread(agent.handle, ctx)
                    findings.extend(agent_findings)
                    all_findings.extend(agent_findings)
                    for f in agent_findings:
                        memory.record_finding(f)
                except Exception as exc:
                    logger.exception("scan_agent failed")
                    findings.append(Finding(
                        agent_name="scan_agent",
                        finding_type="error",
                        target=campaign.target,
                        severity="medium",
                        description=f"Scan agent crashed: {exc}",
                        confidence=1.0,
                    ))
            else:
                # Otherwise, react to open ports published by recon.
                async for finding in queue.subscribe():
                    if budget.exceeded():
                        logger.warning("budget exceeded, scan agent stopping")
                        break

                    if not self._is_open_port_finding(finding):
                        continue
                    if finding.id in processed:
                        continue
                    processed.add(finding.id)

                    port = self._extract_port(finding)
                    logger.info(
                        "scan_agent reacting to open port %s on %s (async)",
                        port,
                        campaign.target,
                    )

                    ctx = make_ctx("scan_agent")
                    ctx.options = {**ctx.options, "port": port, "trigger_finding": finding.id}

                    try:
                        agent_findings = await asyncio.to_thread(agent.handle, ctx)
                        findings.extend(agent_findings)
                        all_findings.extend(agent_findings)
                        for f in agent_findings:
                            memory.record_finding(f)
                    except Exception as exc:
                        logger.exception("scan_agent failed on port %s", port)
                        findings.append(Finding(
                            agent_name="scan_agent",
                            finding_type="error",
                            target=campaign.target,
                            severity="medium",
                            description=f"Scan agent crashed on port {port}: {exc}",
                            confidence=1.0,
                        ))

            self._emit({
                "type": "agent_finished",
                "campaign_id": campaign.id,
                "agent": "scan_agent",
                "findings": len(findings),
                "duration": time.time() - start,
                "timestamp": time.time(),
            })
            logger.info("scan_agent finished: %d findings in %.2fs", len(findings), time.time() - start)
            return findings

        async def run_exploit() -> list[Finding]:
            """Exploit the target.

            If exploit is the primary agent (no recon/scan in the pipeline),
            it runs directly against the target. Otherwise it subscribes to
            the queue and reacts to vulnerabilities immediately.
            """
            agent = self._get_agent("exploit_agent")
            if agent is None:
                logger.warning("exploit_agent not registered, skipping")
                return []
            if "exploit_agent" not in agent_names:
                return []

            self._emit({
                "type": "agent_started",
                "campaign_id": campaign.id,
                "agent": "exploit_agent",
                "target": campaign.target,
                "timestamp": time.time(),
            })
            start = time.time()
            findings: list[Finding] = []

            # If exploit is the primary agent (no recon/scan producing
            # findings), run it directly against the target.
            if "recon_agent" not in agent_names and "scan_agent" not in agent_names:
                ctx = make_ctx("exploit_agent")
                try:
                    agent_findings = await asyncio.to_thread(agent.handle, ctx)
                    findings.extend(agent_findings)
                    all_findings.extend(agent_findings)
                    for f in agent_findings:
                        memory.record_finding(f)
                except Exception as exc:
                    logger.exception("exploit_agent failed")
                    findings.append(Finding(
                        agent_name="exploit_agent",
                        finding_type="error",
                        target=campaign.target,
                        severity="medium",
                        description=f"Exploit agent crashed: {exc}",
                        confidence=1.0,
                    ))
            else:
                # Otherwise, react to vulnerabilities published by scan.
                async for finding in queue.subscribe():
                    if budget.exceeded():
                        logger.warning("budget exceeded, exploit agent stopping")
                        break

                    if not MemoryQueue.is_vulnerability(finding):
                        continue
                    if finding.id in processed:
                        continue
                    processed.add(finding.id)

                    logger.info(
                        "exploit_agent reacting to vulnerability on %s (async)",
                        campaign.target,
                    )

                    ctx = make_ctx("exploit_agent")
                    ctx.options = {**ctx.options, "trigger_finding": finding.id}

                    try:
                        agent_findings = await asyncio.to_thread(agent.handle, ctx)
                        findings.extend(agent_findings)
                        all_findings.extend(agent_findings)
                        for f in agent_findings:
                            memory.record_finding(f)
                    except Exception as exc:
                        logger.exception("exploit_agent failed")
                        findings.append(Finding(
                            agent_name="exploit_agent",
                            finding_type="error",
                            target=campaign.target,
                            severity="medium",
                            description=f"Exploit agent crashed: {exc}",
                            confidence=1.0,
                        ))

            self._emit({
                "type": "agent_finished",
                "campaign_id": campaign.id,
                "agent": "exploit_agent",
                "findings": len(findings),
                "duration": time.time() - start,
                "timestamp": time.time(),
            })
            logger.info("exploit_agent finished: %d findings in %.2fs", len(findings), time.time() - start)
            return findings

        async def run_c2() -> list[Finding]:
            """Run the C2 agent against the target."""
            if "c2_agent" not in agent_names:
                return []
            agent = self._get_agent("c2_agent")
            if agent is None:
                logger.warning("c2_agent not registered, skipping")
                return []
            if budget.exceeded():
                logger.warning("budget exceeded before c2")
                return []

            self._emit({
                "type": "agent_started",
                "campaign_id": campaign.id,
                "agent": "c2_agent",
                "target": campaign.target,
                "timestamp": time.time(),
            })
            start = time.time()
            try:
                findings = await asyncio.to_thread(agent.handle, make_ctx("c2_agent"))
                for f in findings:
                    memory.record_finding(f)
                self._emit({
                    "type": "agent_finished",
                    "campaign_id": campaign.id,
                    "agent": "c2_agent",
                    "findings": len(findings),
                    "duration": time.time() - start,
                    "timestamp": time.time(),
                })
                logger.info("c2_agent finished: %d findings in %.2fs", len(findings), time.time() - start)
                return findings
            except Exception as exc:
                logger.exception("c2_agent failed")
                return [Finding(
                    agent_name="c2_agent",
                    finding_type="error",
                    target=campaign.target,
                    severity="medium",
                    description=f"C2 agent crashed: {exc}",
                    confidence=1.0,
                )]

        async def run_mitm() -> list[Finding]:
            """Run the MITM agent against the target."""
            if "mitm_agent" not in agent_names:
                return []
            agent = self._get_agent("mitm_agent")
            if agent is None:
                logger.warning("mitm_agent not registered, skipping")
                return []
            if budget.exceeded():
                logger.warning("budget exceeded before mitm")
                return []

            self._emit({
                "type": "agent_started",
                "campaign_id": campaign.id,
                "agent": "mitm_agent",
                "target": campaign.target,
                "timestamp": time.time(),
            })
            start = time.time()
            try:
                findings = await asyncio.to_thread(agent.handle, make_ctx("mitm_agent"))
                for f in findings:
                    memory.record_finding(f)
                self._emit({
                    "type": "agent_finished",
                    "campaign_id": campaign.id,
                    "agent": "mitm_agent",
                    "findings": len(findings),
                    "duration": time.time() - start,
                    "timestamp": time.time(),
                })
                logger.info("mitm_agent finished: %d findings in %.2fs", len(findings), time.time() - start)
                return findings
            except Exception as exc:
                logger.exception("mitm_agent failed")
                return [Finding(
                    agent_name="mitm_agent",
                    finding_type="error",
                    target=campaign.target,
                    severity="medium",
                    description=f"MITM agent crashed: {exc}",
                    confidence=1.0,
                )]

        # -- orchestrate the concurrent swarm ------------------------------

        # Start the background subscribers first (they wait on the queue).
        scan_task = asyncio.create_task(run_scan())
        exploit_task = asyncio.create_task(run_exploit())

        # Run recon to completion (it publishes to the queue as it goes).
        recon_findings = await run_recon()
        all_findings.extend(recon_findings)
        for f in recon_findings:
            memory.record_finding(f)

        # Run C2 and MITM agents (they run directly against the target).
        c2_task = asyncio.create_task(run_c2())
        mitm_task = asyncio.create_task(run_mitm())

        # Close the queue so subscribers finish after draining.
        queue.close()

        # Wait for the background agents to finish.
        scan_findings, exploit_findings, c2_findings, mitm_findings = await asyncio.gather(
            scan_task, exploit_task, c2_task, mitm_task
        )
        all_findings.extend(scan_findings)
        all_findings.extend(exploit_findings)
        all_findings.extend(c2_findings)
        all_findings.extend(mitm_findings)

        return all_findings

    # -- helpers -----------------------------------------------------------

    def _get_agent(self, name: str) -> BaseAgent | None:
        with self._lock:
            return self._agents.get(name)

    def _write_to_blackboard(self, campaign_id: str, agent_name: str, finding: Finding) -> None:
        """Write a finding to the blackboard."""
        from core.blackboard import Finding as BlackboardFinding, FindingType
        
        bf = BlackboardFinding(
            campaign_id=campaign_id,
            agent_name=agent_name,
            type=FindingType.RECON,
            target=finding.target,
            data=str(finding.description).encode(),
            pheromone_base=1.0,
        )
        self.blackboard.write(bf)

    def _emit_event(self, event_type: EventType, campaign_id: str, detail: str = "") -> None:
        """Emit a structured event."""
        self.event_emitter.emit(Event(
            type=event_type,
            campaign_id=campaign_id,
            detail=detail,
        ))

    @staticmethod
    def _is_open_port_finding(finding: Finding) -> bool:
        """Check if a finding indicates an open port."""
        meta = finding.metadata or {}
        if meta.get("port") is not None:
            return True
        return "port" in finding.description.lower() and "open" in finding.description.lower()

    @staticmethod
    def _extract_port(finding: Finding) -> int | None:
        """Extract the port number from a finding."""
        meta = finding.metadata or {}
        port = meta.get("port")
        if isinstance(port, int):
            return port
        if isinstance(port, str) and port.isdigit():
            return int(port)
        # Try to parse from description.
        import re
        match = re.search(r"port\s+(\d+)", finding.description, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "agents": list(self._agents.keys()),
                "max_workers": self._max_workers,
                "llm_backend": self._llm.config.backend if self._llm else "none",
                "mode": "async",
            }