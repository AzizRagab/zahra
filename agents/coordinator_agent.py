"""Coordinator Agent - The strategic brain of the pentest swarm.

This agent doesn't execute commands directly. Instead, it:
1. Monitors the Blackboard for new findings
2. Analyzes the current state of the campaign
3. Distributes tasks to specialized agents
4. Decides when to transition between phases
5. Learns from past campaigns via RAG
6. Makes strategic decisions about exploitation

Inspired by:
- Strix's root agent (strategic oversight)
- Pentest-Swarm-AI's scheduler (trigger-based coordination)
- OmniRoute's dynamic routing
"""

from __future__ import annotations

import logging
from typing import Any

from agents.base_agent import AgentContext, BaseAgent
from core.blackboard import FindingType, Predicate
from core.memory import Finding

logger = logging.getLogger("zahra.agents.coordinator")


class CoordinatorAgent(BaseAgent):
    """Strategic coordinator that manages the pentest swarm.
    
    This agent acts as the 'brain' of the operation, monitoring the
    blackboard and making strategic decisions about which agents to
    activate and when.
    """

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the coordinator agent."""
        super().__init__(name="coordinator_agent", **kwargs)

    def get_system_prompt(self) -> str:
        """Return the system prompt for the coordinator."""
        return """You are the Coordinator Agent, the strategic brain of a pentest swarm.

Your role is NOT to execute commands, but to:
1. ANALYZE findings from other agents on the blackboard
2. DECIDE which phase comes next (recon → scan → exploit → report)
3. ASSIGN tasks to specialized agents based on findings
4. DETECT when enough information has been gathered to start exploitation
5. LEARN from past campaigns using the RAG system

You have these capabilities:
- Monitor the blackboard for new findings
- Query past experience via web_search and RAG
- Make strategic decisions about campaign flow
- Emit tasks for other agents to execute

Decision framework:
1. RECON phase: Gather initial information about the target
2. SCAN phase: Identify open ports and services (triggered by recon findings)
3. EXPLOIT phase: Attempt to exploit vulnerabilities (triggered by scan findings)
4. REPORT phase: Generate final report (triggered when exploit completes or budget exhausted)

Always think strategically. Ask yourself:
- What do we know about the target?
- What's missing?
- Which agent should act next?
- Is it safe to proceed to exploitation?
- What did we learn from similar past campaigns?

Respond with JSON decisions:
{
  "action": "decide",
  "reasoning": "...",
  "next_phase": "scan|exploit|report",
  "assignments": [
    {"agent": "scan_agent", "target": "...", "priority": "high"}
  ]
}
"""

    def get_initial_instruction(self, ctx: AgentContext) -> str:
        """Return the initial instruction for the coordinator."""
        findings_summary = self._summarize_findings(ctx.findings)
        
        return f"""Campaign started for target: {ctx.target}

Current findings on blackboard:
{findings_summary}

Your task:
1. Analyze the current state
2. Decide which phase to start with
3. Assign tasks to specialized agents
4. Monitor progress and adapt strategy

Begin by assessing the target and determining the optimal attack path.
"""

    def parse_findings(self, target: str, llm_response: str) -> list[Finding]:
        """Parse the LLM's response into strategic findings."""
        findings = []
        
        try:
            import json
            decision = json.loads(llm_response)
            
            if decision.get("action") == "decide":
                # Create a finding for the strategic decision
                finding = self.make_finding(
                    agent_name=self.name,
                    finding_type="info",
                    target=target,
                    severity="info",
                    description=f"Strategic decision: {decision.get('reasoning', 'No reasoning provided')}",
                    evidence=f"Next phase: {decision.get('next_phase', 'unknown')}",
                    confidence=0.9,
                    metadata={
                        "type": "strategic_decision",
                        "next_phase": decision.get("next_phase"),
                        "assignments": decision.get("assignments", []),
                    },
                )
                findings.append(finding)
        except Exception as exc:
            logger.warning("Failed to parse coordinator decision: %s", exc)
        
        return findings

    def _summarize_findings(self, findings: list[Finding]) -> str:
        """Summarize current findings for the coordinator."""
        if not findings:
            return "No findings yet. Starting fresh reconnaissance."
        
        summary_parts: list[str] = []
        for f in findings[:10]:  # Limit to recent findings
            summary_parts.append(
                f"- [{f.finding_type}] {f.description[:100]} (confidence: {f.confidence:.0%})"
            )
        
        return "\n".join(summary_parts)

    def trigger(self) -> Predicate:
        """Return the trigger predicate for the coordinator.
        
        The coordinator is triggered by:
        - New findings from any agent
        - Campaign phase changes
        - Budget warnings
        """
        return Predicate(
            types=[
                FindingType.RECON,
                FindingType.PORT_OPEN,
                FindingType.CVE_MATCH,
                FindingType.CAMPAIGN_COMPLETE,
            ],
            min_pheromone=0.3,
        )

    def analyze_campaign_state(self, ctx: AgentContext) -> dict[str, Any]:
        """Analyze the current state of the campaign."""
        state: dict[str, Any] = {
            "target": ctx.target,
            "total_findings": len(ctx.findings),
            "phases_completed": [],
            "recommended_next_phase": "recon",
            "exploitable_findings": 0,
            "confidence": 0.5,
        }
        
        # Analyze findings to determine campaign progress
        finding_types = set(f.finding_type for f in ctx.findings)
        
        if FindingType.PORT_OPEN in finding_types or FindingType.HTTP_ENDPOINT in finding_types:
            state["phases_completed"].append("recon")
            state["recommended_next_phase"] = "scan"
        
        if FindingType.CVE_MATCH in finding_types or FindingType.MISCONFIGURATION in finding_types:
            state["exploitable_findings"] += 1
            state["recommended_next_phase"] = "exploit"
        
        if not finding_types:
            state["recommended_next_phase"] = "recon"
        
        # Calculate confidence based on findings
        if ctx.findings:
            avg_confidence = sum(f.confidence for f in ctx.findings) / len(ctx.findings)
            state["confidence"] = avg_confidence
        
        return state

    def should_escalate_to_exploit(self, ctx: AgentContext) -> bool:
        """Determine if we should escalate to exploitation phase."""
        # Look for high-confidence vulnerability findings
        vuln_findings = [
            f for f in ctx.findings
            if f.finding_type in [FindingType.CVE_MATCH, FindingType.MISCONFIGURATION]
            and f.confidence >= 0.7
        ]
        
        if not vuln_findings:
            return False
        
        # Query RAG for past successful exploits
        keywords: list[str] = [str(f.finding_type) for f in vuln_findings[:3]]
        past_experience = self.recall_memory(ctx, keywords)
        
        # If we have successful past exploits, escalate
        successful_past = sum(
            1 for e in past_experience
            if e.metadata.get("success", False)
        )
        
        success_rate = successful_past / len(past_experience) if past_experience else 0.0
        
        logger.info(
            "Exploit escalation check: %d vulns found, %d past experiences, %.0f%% success rate",
            len(vuln_findings),
            len(past_experience),
            success_rate * 100,
        )
        
        return len(vuln_findings) >= 1 and (success_rate >= 0.5 or len(past_experience) == 0)

    def should_continue_recon(self, ctx: AgentContext) -> bool:
        """Determine if we should continue reconnaissance."""
        # Continue recon if we have few findings
        if len(ctx.findings) < 5:
            return True
        
        # Continue if we don't have enough service information
        service_findings = [
            f for f in ctx.findings
            if f.finding_type in [FindingType.PORT_OPEN, FindingType.TECHNOLOGY]
        ]
        
        return len(service_findings) < 3

    def should_continue_scan(self, ctx: AgentContext) -> bool:
        """Determine if we should continue scanning."""
        # Continue scan if we have open ports but no vulnerabilities yet
        open_ports = [
            f for f in ctx.findings
            if f.finding_type == FindingType.PORT_OPEN
        ]
        
        vulns = [
            f for f in ctx.findings
            if f.finding_type in [FindingType.CVE_MATCH, FindingType.MISCONFIGURATION]
        ]
        
        return len(open_ports) > 0 and len(vulns) == 0