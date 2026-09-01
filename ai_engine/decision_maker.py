"""Decision maker — parses strict JSON decisions from the LLM.

The decision maker expects the LLM to return ONLY JSON in this format:

    {"action": "run_command", "command": "nmap -sV -p- <target>", "reasoning": "..."}

Or:

    {"action": "done", "summary": "Found open ports 22,80"}

Or:

    {"action": "finding", "type": "vuln", "severity": "critical", "description": "...", ...}

The parser extracts the JSON, validates the action, and returns a
Decision object. If the LLM returns non-JSON text, the parser attempts
to extract JSON from the text, and falls back to an error decision.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from ai_engine.llm_wrapper import LLMWrapper
from ai_engine.prompt_engineer import PromptEngineer
from core.memory import Finding, MemoryEntry, MemoryStore

logger = logging.getLogger("zahra.ai_engine.decision")


# Severity weight for prioritization (higher = more important)
SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 3,
    "info": 1,
}


@dataclass
class Decision:
    """A parsed decision from the LLM's JSON response.

    Attributes:
        action: "run_command", "done", "finding", or "error"
        command: The command to execute (if action is "run_command")
        reasoning: Why this command/decision was made
        summary: Completion summary (if action is "done")
        finding: Parsed finding dict (if action is "finding")
        raw: The raw LLM response (for debugging)
    """

    action: str = "error"
    command: str = ""
    reasoning: str = ""
    summary: str = ""
    finding: dict[str, Any] = field(default_factory=dict[str, Any])
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "command": self.command,
            "reasoning": self.reasoning,
            "summary": self.summary,
            "finding": self.finding,
        }


class DecisionMaker:
    """Parses strict JSON decisions from the LLM for the zahra platform."""

    def __init__(
        self,
        llm: LLMWrapper | None = None,
        prompt_engineer: PromptEngineer | None = None,
    ) -> None:
        self.llm = llm or LLMWrapper()
        self.prompts = prompt_engineer or PromptEngineer()

    # -- JSON parsing ------------------------------------------------------

    def parse_decision(self, llm_response: str) -> Decision:
        """Parse the LLM's JSON response into a Decision.

        Expected JSON formats:
            {"action": "run_command", "command": "...", "reasoning": "..."}
            {"action": "done", "summary": "..."}
            {"action": "finding", "type": "vuln", "severity": "...", ...}
        """
        parsed = self._extract_json(llm_response)

        if parsed is None:
            # Could not parse JSON — return error decision
            return Decision(
                action="error",
                raw=llm_response,
                reasoning="LLM did not return valid JSON",
            )

        action = str(parsed.get("action", "error")).lower().strip()

        if action == "run_command":
            return Decision(
                action="run_command",
                command=str(parsed.get("command", "")),
                reasoning=str(parsed.get("reasoning", "")),
                raw=llm_response,
            )

        elif action == "done":
            return Decision(
                action="done",
                summary=str(parsed.get("summary", "")),
                reasoning=str(parsed.get("reasoning", "")),
                raw=llm_response,
            )

        elif action == "finding":
            return Decision(
                action="finding",
                finding=parsed,
                reasoning=str(parsed.get("reasoning", "")),
                raw=llm_response,
            )

        else:
            # Unknown action — treat as error
            return Decision(
                action="error",
                raw=llm_response,
                reasoning=f"Unknown action: {action}",
            )

    def _extract_json(self, response: str) -> dict[str, Any] | None:
        """Extract a JSON object from the LLM response - AGGRESSIVE MODE.

        Tries multiple strategies to extract JSON:
        1. Direct JSON parse
        2. Extract from first { to last }
        3. Extract from ```json blocks
        4. Extract from ``` blocks
        5. Try to fix common JSON errors
        6. If all fails, return a fallback run_command decision
        """
        response = response.strip()

        # 1. Direct JSON parse
        try:
            result = json.loads(response)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

        # 2. Extract from first { to last }
        first_brace = response.find("{")
        last_brace = response.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            json_str = response[first_brace:last_brace + 1]
            try:
                result = json.loads(json_str)
                if isinstance(result, dict):
                    return result
            except (json.JSONDecodeError, ValueError):
                # Try to fix common JSON errors
                fixed = self._fix_json(json_str)
                if fixed:
                    try:
                        result = json.loads(fixed)
                        if isinstance(result, dict):
                            return result
                    except (json.JSONDecodeError, ValueError):
                        pass

        # 3. Extract from ```json blocks
        if "```json" in response:
            start = response.index("```json") + 7
            end = response.index("```", start)
            json_str = response[start:end].strip()
            try:
                result = json.loads(json_str)
                if isinstance(result, dict):
                    return result
            except (json.JSONDecodeError, ValueError):
                pass

        # 4. Try without ```json but with ```
        if "```" in response:
            parts = response.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    try:
                        result = json.loads(part)
                        if isinstance(result, dict):
                            return result
                    except (json.JSONDecodeError, ValueError):
                        pass

        # 5. Try to extract command from bash blocks (LLM sometimes wraps commands)
        if "```bash" in response or "```sh" in response:
            import re
            bash_match = re.search(r'```(?:bash|sh)?\s*\n?(.*?)\n?```', response, re.DOTALL)
            if bash_match:
                command = bash_match.group(1).strip()
                if command:
                    return {
                        "action": "run_command",
                        "command": command,
                        "reasoning": "Extracted from bash block"
                    }

        # 6. If LLM mentioned nmap or any tool, try to extract the command
        import re
        cmd_match = re.search(r'(nmap|masscan|nuclei|sqlmap|nikto|gobuster|curl|searchsploit|metasploit|msfconsole)\s+[\w\-\.:/]+', response)
        if cmd_match:
            return {
                "action": "run_command",
                "command": cmd_match.group(0),
                "reasoning": "Extracted command from LLM response"
            }

        logger.warning("could not extract JSON from LLM response: %s", response[:200])
        return None

    @staticmethod
    def _fix_json(json_str: str) -> str | None:
        """Try to fix common JSON errors."""
        # Remove trailing commas
        import re
        fixed = re.sub(r',\s*}', '}', json_str)
        fixed = re.sub(r',\s*]', ']', fixed)
        # Fix single quotes to double quotes
        fixed = fixed.replace("'", '"')
        return fixed

    # -- finding extraction ------------------------------------------------

    def finding_from_decision(self, target: str, decision: Decision) -> Finding | None:
        """Convert a "finding" action decision into a Finding object."""
        if decision.action != "finding" or not decision.finding:
            return None

        data = decision.finding
        return Finding(
            agent_name="decision_maker",
            finding_type=str(data.get("type", "vuln")),
            target=target,
            severity=str(data.get("severity", "medium")),
            description=str(data.get("description", "")),
            evidence=str(data.get("evidence", "")),
            confidence=float(data.get("confidence", 0.7)),
            metadata=data.get("metadata", {}),
        )

    # -- planning ----------------------------------------------------------

    def plan_next_step(
        self,
        target: str,
        findings: list[Finding],
        memory: MemoryStore | None = None,
    ) -> Decision:
        """Ask the LLM for the next command to run."""
        if self.llm.is_offline:
            return self._heuristic_plan(target, findings)

        memory_entries: list[MemoryEntry] = []
        if memory is not None:
            memory_entries = memory.recall_relevant([target])

        system: str = self.prompts.get_prompt("scan")
        user_prompt: str = f"Target: {target}\nFindings: {len(findings)}\nMemory: {len(memory_entries)}"
        try:
            response = self.llm.complete(user_prompt, system=system)
            return self.parse_decision(response)
        except Exception:
            logger.exception("LLM planning failed; falling back to heuristics")
            return self._heuristic_plan(target, findings)

    # -- prioritization ----------------------------------------------------

    def prioritize_findings(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings by exploitability and impact."""
        return sorted(
            findings,
            key=lambda f: SEVERITY_WEIGHT.get(f.severity, 0) * f.confidence,
            reverse=True,
        )

    def build_attack_chain(self, findings: list[Finding]) -> list[str]:
        """Construct an attack chain from individual findings."""
        if not findings:
            return []

        chain: list[str] = []
        recon = [f for f in findings if f.finding_type == "recon"]
        chain.extend(f.id for f in self.prioritize_findings(recon))

        vulns = [f for f in findings if f.finding_type == "vuln"]
        chain.extend(f.id for f in self.prioritize_findings(vulns))

        creds = [f for f in findings if f.finding_type == "credential"]
        chain.extend(f.id for f in creds)

        return chain

    def filter_false_positives(self, findings: list[Finding]) -> list[Finding]:
        """Remove likely false positives."""
        return [f for f in findings if f.confidence >= 0.3]

    # -- heuristic fallback ------------------------------------------------

    def _heuristic_plan(self, target: str, findings: list[Finding]) -> Decision:
        """Rule-based planning when no LLM is available."""
        if not findings:
            return Decision(
                action="run_command",
                command=f"nmap -sV -T4 --top-ports 100 {target}",
                reasoning="No findings yet; starting with nmap top ports scan.",
            )

        has_recon = any(f.finding_type == "recon" for f in findings)
        has_vuln = any(f.finding_type == "vuln" for f in findings)
        has_exploit = any(
            f.finding_type == "vuln" and f.severity in ("high", "critical")
            for f in findings
        )

        if has_recon and not has_vuln:
            return Decision(
                action="run_command",
                command=f"nmap --script vuln -p- {target}",
                reasoning="Recon complete; running vulnerability scripts.",
            )

        if has_vuln and not has_exploit:
            return Decision(
                action="run_command",
                command=f"nuclei -u http://{target} -silent",
                reasoning="Vulnerabilities found; running nuclei scan.",
            )

        if has_exploit:
            return Decision(
                action="done",
                summary=f"High-severity findings detected on {target}. Ready for exploitation.",
            )

        return Decision(
            action="run_command",
            command=f"nmap -sV -T4 {target}",
            reasoning="Continuing with service detection scan.",
        )