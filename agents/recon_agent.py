"""Reconnaissance agent — LLM-driven recon that plans and executes commands.

The recon agent is the first agent in the swarm pipeline. It:
1. Receives a target from the orchestrator
2. Asks the LLM to plan reconnaissance commands
3. Executes the commands in the terminal (nmap, dnsrecon, etc.)
4. Feeds the output back to the LLM for analysis
5. Passes findings to the next agent (scan_agent)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_agent import AgentContext, BaseAgent
from core.memory import Finding
from core.tactical_intel import TacticalIntel

logger = logging.getLogger("zahra.agents.recon")


class ReconAgent(BaseAgent):
    """LLM-driven reconnaissance agent."""

    def __init__(
        self,
        *,
        llm_wrapper: Any | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            "recon_agent",
            llm_wrapper=llm_wrapper,
            max_iterations=max_iterations,
            max_concurrency=3,
        )

    def get_system_prompt(self) -> str:
        from ai_engine.prompt_engineer import PromptEngineer
        return PromptEngineer().get_prompt("recon")

    def _prepare_tactical_context(self, ctx: AgentContext, *, query: str | None = None) -> str:
        """Build a fused context bundle (web + RAG) for the LLM prompt."""
        intel = TacticalIntel.get()
        q = query or ctx.target
        fused = intel.fused_context(q, include_web=True, top_k=3)
        return fused

    def get_initial_instruction(self, ctx: AgentContext) -> str:
        target = ctx.target
        prev_findings = self._build_context_from_findings(ctx.findings)

        # Also include any memory entries
        memory_ctx = ""
        if ctx.memory:
            past = ctx.memory.recall_relevant([target])
            if past:
                memory_ctx = "\n### Memory (past knowledge):\n"
                for m in past[:5]:
                    memory_ctx += f"- {m.pattern}\n"

        # Tactical intelligence layer (web + RAG)
        tactical_ctx = self._prepare_tactical_context(ctx)

        instruction = (
            f"Target: {target}\n\n"
            f"Previous findings: {prev_findings}\n\n"
            f"{memory_ctx}\n\n"
            f"[Tactical Context: web intelligence + semantic recall loaded]\n\n"
            "Begin reconnaissance NOW. Respond with JSON only."
        )
        return instruction

    def _offline_command(self, target: str) -> str:
        """Offline recon command — nmap top-ports scan."""
        return f"nmap -sV -T4 --top-ports 100 {target}"

    def parse_findings(self, target: str, llm_response: str) -> list[Finding]:
        """Parse the LLM's final DONE response into structured findings."""
        findings: list[Finding] = []

        # Try to extract JSON from the response
        import json as json_module
        json_match = re.search(r"```json\s*(.*?)\s*```", llm_response, re.DOTALL)
        if json_match:
            try:
                data = json_module.loads(json_match.group(1))
                for item in data.get("findings", []):
                    findings.append(
                        self.make_finding(
                            agent_name=self.name,
                            finding_type=item.get("type", "recon"),
                            target=target,
                            severity=item.get("severity", "info"),
                            description=item.get("description", ""),
                            evidence=item.get("evidence", ""),
                            confidence=item.get("confidence", 0.7),
                            metadata=item.get("metadata", {}),
                        )
                    )
                return findings
            except (json_module.JSONDecodeError, KeyError):
                logger.warning("failed to parse JSON findings from LLM response")

        # Fallback: parse the text summary
        for line in llm_response.splitlines():
            line = line.strip()
            if not line or line.startswith("DONE:"):
                continue

            # Detect open ports
            port_match = re.search(r"port\s+(\d+)(?:/tcp)?", line, re.IGNORECASE)
            if port_match:
                port = int(port_match.group(1))
                service_match = re.search(r"(\w+)\s*(?:service)?", line, re.IGNORECASE)
                service = service_match.group(1) if service_match else "unknown"
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="recon",
                        target=target,
                        severity="info",
                        description=f"Open port {port}/tcp — {service}",
                        evidence=line,
                        confidence=0.85,
                        metadata={"port": port, "service": service},
                    )
                )

            # Detect DNS resolution
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match and "resolve" in line.lower():
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="recon",
                        target=target,
                        severity="info",
                        description=f"DNS resolution: {target} → {ip_match.group(1)}",
                        evidence=line,
                        confidence=0.9,
                        metadata={"ip": ip_match.group(1)},
                    )
                )

        # If no structured findings were parsed, create a summary finding
        if not findings:
            summary = llm_response.replace("DONE:", "").strip()[:500]
            findings.append(
                self.make_finding(
                    agent_name=self.name,
                    finding_type="recon",
                    target=target,
                    severity="info",
                    description=f"Reconnaissance summary: {summary}",
                    evidence=llm_response[:1000],
                    confidence=0.6,
                )
            )

        return findings