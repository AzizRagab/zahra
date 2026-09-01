"""MITM Agent — Man-in-the-Middle agent for ZAHRA v3.0.

This agent performs network interception attacks:
1. ARP spoofing to intercept traffic
2. DNS spoofing to redirect victims
3. SSL stripping to downgrade HTTPS
4. Credential harvesting from intercepted traffic
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_agent import AgentContext, BaseAgent
from core.memory import Finding

logger = logging.getLogger("zahra.agents.mitm")


class MITMAgent(BaseAgent):
    """Man-in-the-Middle agent — intercepts and manipulates network traffic."""

    def __init__(
        self,
        *,
        llm_wrapper: Any | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            "mitm_agent",
            llm_wrapper=llm_wrapper,
            max_iterations=max_iterations,
            max_concurrency=1,
        )

    def get_system_prompt(self) -> str:
        from ai_engine.prompt_engineer import PromptEngineer
        return PromptEngineer().get_prompt("mitm")

    def get_initial_instruction(self, ctx: AgentContext) -> str:
        target = ctx.target
        prev_findings = self._build_context_from_findings(ctx.findings)

        return f"""Target: {target}

Previous findings: {prev_findings}

Begin MITM operations NOW. Intercept network traffic and harvest credentials.
Respond with JSON only."""

    def _offline_command(self, target: str) -> str:
        """Offline MITM command — simulate ARP spoofing."""
        return f"echo 'Simulating ARP spoofing attack on {target}'"

    def parse_findings(self, target: str, llm_response: str) -> list[Finding]:
        """Parse MITM findings from LLM response."""
        findings: list[Finding] = []

        import json as json_module
        json_match = re.search(r"```json\s*(.*?)\s*```", llm_response, re.DOTALL)
        if json_match:
            try:
                data = json_module.loads(json_match.group(1))
                for item in data.get("findings", []):
                    findings.append(
                        self.make_finding(
                            agent_name=self.name,
                            finding_type=item.get("type", "mitm"),
                            target=target,
                            severity=item.get("severity", "high"),
                            description=item.get("description", ""),
                            evidence=item.get("evidence", ""),
                            confidence=item.get("confidence", 0.85),
                            metadata=item.get("metadata", {}),
                        )
                    )
                return findings
            except (json_module.JSONDecodeError, KeyError):
                logger.warning("failed to parse JSON findings from MITM response")

        # Fallback: detect MITM patterns
        for line in llm_response.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detect ARP spoofing
            if any(kw in line.lower() for kw in ["arp", "spoof", "arpspoof", "bettercap"]):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="mitm",
                        target=target,
                        severity="high",
                        description=f"ARP spoofing: {line[:200]}",
                        evidence=line,
                        confidence=0.85,
                        metadata={"type": "arp_spoof"},
                    )
                )

            # Detect DNS spoofing
            if any(kw in line.lower() for kw in ["dns", "spoof", "redirect", "dnsspoof"]):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="mitm",
                        target=target,
                        severity="high",
                        description=f"DNS spoofing: {line[:200]}",
                        evidence=line,
                        confidence=0.85,
                        metadata={"type": "dns_spoof"},
                    )
                )

            # Detect SSL stripping
            if any(kw in line.lower() for kw in ["ssl", "strip", "downgrade", "https"]):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="mitm",
                        target=target,
                        severity="critical",
                        description=f"SSL stripping: {line[:200]}",
                        evidence=line,
                        confidence=0.9,
                        metadata={"type": "ssl_strip"},
                    )
                )

            # Detect credential harvesting
            if any(kw in line.lower() for kw in ["credential", "password", "harvest", "capture"]):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="mitm",
                        target=target,
                        severity="critical",
                        description=f"Credential harvest: {line[:200]}",
                        evidence=line,
                        confidence=0.9,
                        metadata={"type": "credential_harvest"},
                    )
                )

        if not findings:
            findings.append(
                self.make_finding(
                    agent_name=self.name,
                    finding_type="mitm",
                    target=target,
                    severity="info",
                    description=f"MITM summary: {llm_response[:500]}",
                    evidence=llm_response[:1000],
                    confidence=0.6,
                )
            )

        return findings