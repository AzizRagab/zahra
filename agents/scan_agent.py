"""Scanning agent — LLM-driven vulnerability scanner.

The scan agent is the second agent in the swarm pipeline. It:
1. Receives a target + recon findings from the previous agent
2. Asks the LLM to plan scanning commands based on the recon data
3. Executes the commands (nuclei, nikto, nmap -sV, etc.)
4. Feeds the output back to the LLM for analysis
5. Passes vulnerability findings to the next agent (exploit_agent)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_agent import AgentContext, BaseAgent
from core.memory import Finding
from core.tactical_intel import TacticalIntel

logger = logging.getLogger("zahra.agents.scan")


class ScanAgent(BaseAgent):
    """LLM-driven vulnerability scanning agent."""

    def __init__(
        self,
        *,
        llm_wrapper: Any | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            "scan_agent",
            llm_wrapper=llm_wrapper,
            max_iterations=max_iterations,
            max_concurrency=2,
        )

    def get_system_prompt(self) -> str:
        from ai_engine.prompt_engineer import PromptEngineer
        return PromptEngineer().get_prompt("scan")

    def get_initial_instruction(self, ctx: AgentContext) -> str:
        target = ctx.target
        prev_findings = self._build_context_from_findings(ctx.findings)

        return f"""Target: {target}

Previous findings: {prev_findings}

Begin vulnerability scanning NOW. Respond with JSON only."""

    def _offline_command(self, target: str) -> str:
        """Offline scan command — nuclei template scan."""
        return f"nuclei -u http://{target} -silent"

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
                            finding_type=item.get("type", "vuln"),
                            target=target,
                            severity=item.get("severity", "medium"),
                            description=item.get("description", ""),
                            evidence=item.get("evidence", ""),
                            confidence=item.get("confidence", 0.7),
                            metadata=item.get("metadata", {}),
                        )
                    )
                return findings
            except (json_module.JSONDecodeError, KeyError):
                logger.warning("failed to parse JSON findings from LLM response")

        # Fallback: parse text for vulnerability patterns
        for line in llm_response.splitlines():
            line = line.strip()
            if not line or line.startswith("DONE:"):
                continue

            # Detect CVE references
            cve_match = re.search(r"CVE-\d{4}-\d+", line, re.IGNORECASE)
            if cve_match:
                severity = "high"
                if "critical" in line.lower():
                    severity = "critical"
                elif "medium" in line.lower():
                    severity = "medium"
                elif "low" in line.lower():
                    severity = "low"
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="vuln",
                        target=target,
                        severity=severity,
                        description=line,
                        evidence=cve_match.group(0),
                        confidence=0.85,
                        metadata={"cve": cve_match.group(0)},
                    )
                )

            # Detect service versions
            version_match = re.search(r"(\w+)\s+(\d+\.\d+(?:\.\d+)?)", line)
            if version_match and "version" in line.lower():
                service, version = version_match.groups()
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="vuln",
                        target=target,
                        severity="info",
                        description=f"Service: {service} {version}",
                        evidence=line,
                        confidence=0.8,
                        metadata={"service": service, "version": version},
                    )
                )

        # If no structured findings were parsed, create a summary finding
        if not findings:
            summary = llm_response.replace("DONE:", "").strip()[:500]
            findings.append(
                self.make_finding(
                    agent_name=self.name,
                    finding_type="vuln",
                    target=target,
                    severity="info",
                    description=f"Scan summary: {summary}",
                    evidence=llm_response[:1000],
                    confidence=0.6,
                )
            )

        return findings
