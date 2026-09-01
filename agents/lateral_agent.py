"""Lateral Movement Agent — post-exploitation network expansion for ZAHRA.

Activates after a successful Exploit Agent run. This agent:
1. Enumerates the compromised host's internal network neighborhood
2. Discovers additional live hosts / services on the same subnet
3. Attempts credential reuse (discovered credentials) against adjacent hosts
4. Records lateral-movement findings for the blackboard

All operations are operator-directed and intended strictly for authorized
engagements.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_agent import AgentContext, BaseAgent
from core.memory import Finding

logger = logging.getLogger("zahra.agents.lateral")

_SYSTEM_PROMPT = """You are the Lateral Movement agent in an AUTHORIZED penetration
testing engagement, operating under explicit operator direction and within the
authorized scope.

Your mission after a successful initial compromise:
1. Map the internal network reachable from the compromised host
2. Identify adjacent live hosts, open services, and trust relationships
3. Test credential reuse (discovered credentials only) against adjacent hosts
4. Prioritize stealth, safety, and scope compliance — never touch targets
   outside the authorized scope

Respond with STRICT JSON only, either:
{"action": "run_command", "command": "...", "reasoning": "..."}
or
{"action": "done", "summary": "...", "findings": [{"type": "...", "severity": "...",
"description": "...", "evidence": "...", "confidence": 0.9}]}

Allowed tools: nmap, netexec/crackmapexec, smbclient, impacket suites,
arp -a, ip route, netstat. Never destructive."""


class LateralAgent(BaseAgent):
    """Lateral Movement agent — expands access across the internal network."""

    def __init__(
        self,
        *,
        llm_wrapper: Any | None = None,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            "lateral_agent",
            llm_wrapper=llm_wrapper,
            max_iterations=max_iterations,
            max_concurrency=1,
        )

    def get_system_prompt(self) -> str:
        return _SYSTEM_PROMPT

    def get_initial_instruction(self, ctx: AgentContext) -> str:
        target = ctx.target
        prev_findings = self._build_context_from_findings(ctx.findings)

        # Harvest credentials discovered by earlier agents for reuse testing
        creds: list[str] = []
        for f in ctx.findings:
            text = f"{getattr(f, 'description', '')} {getattr(f, 'evidence', '')}"
            for m in re.finditer(r"([A-Za-z0-9_.\\-]{2,32}):([^\s:]{4,64})", text):
                creds.append(m.group(0))
        cred_note = ("\n\nDiscovered credentials (test reuse ONLY on in-scope hosts): "
                     + ", ".join(creds[:10])) if creds else ""

        return f"""Compromised entry point: {target}

Previous findings: {prev_findings}{cred_note}

Begin lateral movement assessment NOW. Enumerate the internal network from the
compromised host, discover adjacent in-scope hosts, and test credential reuse.
Respond with JSON only."""

    def parse_findings(self, target: str, llm_response: str) -> list[Finding]:
        """Parse lateral-movement findings from the LLM's final DONE response."""
        import json as json_module

        findings: list[Finding] = []

        # 1) fenced ```json ... ``` block
        json_match = re.search(r"```json\s*(.*?)\s*```", llm_response, re.DOTALL)
        # 2) bare JSON object fallback
        if not json_match:
            brace = re.search(r"\{.*\}", llm_response, re.DOTALL)
            if brace:
                json_match = brace
        if json_match:
            try:
                # fenced ```json ... ``` block → group(1) is content
                # bare {...} fallback → no capture group → group(0)
                raw = json_match.group(1) if json_match.re.groups >= 1 else json_match.group(0)
                data = json_module.loads(raw)
                for item in data.get("findings", []):
                    findings.append(
                        self.make_finding(
                            agent_name=self.name,
                            finding_type=item.get("type", "lateral_movement"),
                            target=item.get("target", target),
                            severity=item.get("severity", "high"),
                            description=item.get("description", ""),
                            evidence=item.get("evidence", ""),
                            confidence=item.get("confidence", 0.85),
                            metadata=item.get("metadata", {}),
                        )
                    )
                if findings:
                    return findings
            except (json_module.JSONDecodeError, KeyError, TypeError):
                logger.warning("failed to parse JSON findings from lateral response")

        # 3) heuristic fallback: detect lateral-movement signals in plain text
        for line in llm_response.splitlines():
            low = line.lower().strip()
            if not low:
                continue
            if any(kw in low for kw in (
                "credential reuse", "smb", "netexec", "crackmapexec",
                "pass-the-hash", "pth", "wmiexec", "psexec", "impacket",
                "adjacent host", "lateral",
            )):
                findings.append(
                    self.make_finding(
                        agent_name=self.name,
                        finding_type="lateral_movement",
                        target=target,
                        severity="high",
                        description=f"Lateral movement signal: {line.strip()[:200]}",
                        evidence=line.strip(),
                        confidence=0.7,
                        metadata={"type": "credential_reuse"},
                    )
                )
        return findings
