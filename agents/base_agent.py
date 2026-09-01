"""Base agent — LLM-driven swarm agent with JSON decision parsing.

Each agent follows this loop:
1. Receive a target + context from previous agents
2. Ask the LLM: "What command should I run?"
3. LLM returns strict JSON: {"action": "run_command", "command": "...", "reasoning": "..."}
4. Agent extracts the command from JSON and executes it in the terminal
5. Agent sends the output back to the LLM
6. LLM either returns another command JSON or {"action": "done", "summary": "..."}
7. Findings are recorded and passed to the next agent

The agent does NOT print plain text — it only processes JSON decisions.

Enhanced with:
- Skills system (modular capabilities)
- Tools framework
- Event emission for observability
- Blackboard integration for stigmergic coordination
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ai_engine.decision_maker import DecisionMaker
from core.blackboard import Blackboard, Predicate
from core.events import Event, EventEmitter, EventType, get_emitter
from core.memory import Finding, MemoryEntry, MemoryQueue, MemoryStore

logger = logging.getLogger("zahra.agents.base")


@dataclass
class AgentContext:
    """Context passed to an agent when it is invoked.

    Attributes:
        target: The target host / IP / URL.
        memory: Shared memory store for cross-agent knowledge.
        queue: Async memory queue for stigmergic coordination.
        options: Free-form options from the router / orchestrator.
        budget: Current budget state (mutable; agents may read).
        findings: Findings discovered so far by the swarm (read-only view).
        blackboard: Shared blackboard for stigmergic coordination.
        skills: List of available skills for this agent.
        event_emitter: Event emitter for observability.
    """

    target: str = ""
    memory: MemoryStore | None = None
    queue: MemoryQueue | None = None
    options: dict[str, Any] = field(default_factory=dict[str, Any])
    budget: Any | None = None
    findings: list[Finding] = field(default_factory=list[Finding])
    blackboard: Blackboard | None = None
    skills: list[Any] = field(default_factory=list[Any])
    event_emitter: EventEmitter | None = None


class BaseAgent(ABC):
    """Abstract base class for all zahra swarm agents.

    The agent uses an LLM-driven loop with strict JSON parsing:
    1. LLM returns {"action": "run_command", "command": "...", ...}
    2. Agent extracts command and executes it
    3. Output is fed back to the LLM
    4. LLM returns another command or {"action": "done", "summary": "..."}

    Enhanced with skills, tools, events, and blackboard integration.
    """

    def __init__(
        self,
        name: str,
        *,
        llm_wrapper: Any | None = None,
        max_iterations: int = 10,
        max_concurrency: int = 1,
        skills: list[Any] | None = None,
        blackboard: Blackboard | None = None,
        event_emitter: EventEmitter | None = None,
    ) -> None:
        self.name = name
        self.llm = llm_wrapper
        self.max_iterations = max_iterations
        self.max_concurrency = max(1, max_concurrency)
        self.decision_maker = DecisionMaker(llm_wrapper)
        self.skills = skills or []
        self.blackboard = blackboard
        self.event_emitter = event_emitter or get_emitter()

    # -- contract ----------------------------------------------------------

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt that defines this agent's persona."""
        ...

    @abstractmethod
    def get_initial_instruction(self, ctx: AgentContext) -> str:
        """Return the first message to send to the LLM (includes target + context)."""
        ...

    @abstractmethod
    def parse_findings(self, target: str, llm_response: str) -> list[Finding]:
        """Parse the LLM's final response into structured findings."""
        ...

    # -- trigger predicate (for stigmergic coordination) --------------------

    def trigger(self) -> Predicate:
        """Return the trigger predicate for this agent.
        
        Defines what findings this agent should process.
        Override in subclasses for custom trigger logic.
        """
        return Predicate()

    # -- main execution loop ----------------------------------------------

    def handle(self, ctx: AgentContext) -> list[Finding]:
        """Run the LLM-driven plan-execute-observe loop with JSON parsing.

        1. Send the target + context to the LLM
        2. LLM returns JSON: {"action": "run_command", "command": "...", ...}
        3. Agent extracts command from JSON and executes it
        4. Send the output back to the LLM
        5. Repeat until {"action": "done"} or max_iterations
        6. Parse findings from the final LLM response
        """
        if not ctx.target:
            return [
                self.make_finding(
                    agent_name=self.name,
                    finding_type="error",
                    target=ctx.target,
                    severity="low",
                    description="No target specified.",
                    confidence=1.0,
                )
            ]

        # Emit agent started event
        self._emit_event(EventType.AGENT_STARTED, ctx, detail=f"Starting {self.name}")

        logger.info("%s starting for target: %s", self.name, ctx.target)

        system_prompt = self.get_system_prompt()
        conversation: list[dict[str, str]] = []

        # Initial instruction with target + context from previous agents
        initial_msg = self.get_initial_instruction(ctx)
        conversation.append({"role": "user", "content": initial_msg})

        all_findings: list[Finding] = []
        final_response = ""

        for iteration in range(self.max_iterations):
            logger.debug("%s iteration %d", self.name, iteration + 1)

            # Ask the LLM what to do next
            llm_response = self._ask_llm(system_prompt, conversation, ctx)
            final_response = llm_response

            # Parse the JSON decision
            decision = self.decision_maker.parse_decision(llm_response)

            # Handle the decision
            if decision.action == "done":
                logger.info("%s LLM signaled done at iteration %d: %s", self.name, iteration + 1, decision.summary)
                break

            elif decision.action == "run_command":
                # Extract command from JSON and execute it
                command = decision.command.strip()
                if not command:
                    # Empty command — nudge the LLM
                    conversation.append({"role": "assistant", "content": llm_response})
                    conversation.append({
                        "role": "user",
                        "content": json.dumps({
                            "status": "error",
                            "message": "Empty command in run_command action. Provide a valid command or respond with done.",
                            "instruction": "Respond with JSON only."
                        })
                    })
                    continue

                logger.info("%s executing: %s (%s)", self.name, command, decision.reasoning)

                # Emit tool used event
                self._emit_event(EventType.TOOL_USED, ctx, detail=command)

                # Execute the command in the terminal
                rc, stdout, stderr = self.run_tool(command, timeout=ctx.options.get("timeout", 120))

                # Record the command execution as a finding
                cmd_finding = self._finding_from_command(ctx.target, command, rc, stdout, stderr)
                if cmd_finding:
                    all_findings.append(cmd_finding)
                    self.record_to_memory(ctx, cmd_finding)
                    self.publish_to_queue(ctx, cmd_finding)
                    self._write_to_blackboard(ctx, cmd_finding)

                # Auto-Evasion: if the command was blocked/failed, ask the LLM
                # to suggest an alternative tool or evasion flag instead of
                # stopping or repeating the same command.
                if self._detect_blocked(stdout, stderr, rc):
                    logger.warning(
                        "%s command appears blocked/failed: %s",
                        self.name,
                        command,
                    )
                    evasion = self._build_evasion_prompt(command, stdout, stderr, rc)
                    conversation.append({"role": "assistant", "content": llm_response})
                    conversation.append({"role": "user", "content": evasion})
                    continue

                # Feed the output back to the LLM as JSON observation
                conversation.append({"role": "assistant", "content": llm_response})
                obs = self._format_observation(command, rc, stdout, stderr)
                conversation.append({"role": "user", "content": obs})

            elif decision.action == "finding":
                # LLM reported a finding — record it
                finding = self.decision_maker.finding_from_decision(ctx.target, decision)
                if finding:
                    finding.agent_name = self.name
                    all_findings.append(finding)
                    self.record_to_memory(ctx, finding)
                    self.publish_to_queue(ctx, finding)
                    self._write_to_blackboard(ctx, finding)

                conversation.append({"role": "assistant", "content": llm_response})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "status": "finding_recorded",
                        "instruction": "Continue with the next command or respond with done."
                    })
                })

            elif decision.action == "skill":
                # LLM requested a skill execution
                skill_result = self._execute_skill_from_decision(ctx, decision)
                conversation.append({"role": "assistant", "content": llm_response})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "status": "skill_executed",
                        "result": skill_result,
                        "instruction": "Continue with the next command or respond with done."
                    })
                })

            elif decision.action == "error":
                # LLM did not return valid JSON — nudge it
                logger.warning("%s LLM returned non-JSON at iteration %d", self.name, iteration + 1)
                conversation.append({"role": "assistant", "content": llm_response})
                conversation.append({
                    "role": "user",
                    "content": json.dumps({
                        "status": "error",
                        "message": "Your response was not valid JSON. You MUST respond with ONLY a JSON object.",
                        "expected_format": {
                            "run_command": {"action": "run_command", "command": "your command here", "reasoning": "why"},
                            "done": {"action": "done", "summary": "your summary here"}
                        },
                        "instruction": "Respond with JSON only. No markdown, no prose."
                    })
                })

        # Parse final findings from the LLM's last response
        parsed_findings = self.parse_findings(ctx.target, final_response)
        all_findings.extend(parsed_findings)

        # Record all findings to memory for downstream agents
        for f in all_findings:
            self.record_to_memory(ctx, f)
            self.publish_to_queue(ctx, f)
            self._write_to_blackboard(ctx, f)

        # Emit agent finished event
        self._emit_event(
            EventType.AGENT_FINISHED, ctx,
            detail=f"Completed: {len(all_findings)} findings"
        )

        logger.info("%s finished: %d findings", self.name, len(all_findings))
        return all_findings

    # -- event helpers ------------------------------------------------------

    def _emit_event(self, event_type: EventType, ctx: AgentContext, detail: str = "") -> None:
        """Emit an event if event emitter is available."""
        if self.event_emitter and ctx:
            self.event_emitter.emit(Event(
                type=event_type,
                campaign_id=ctx.options.get("campaign_id", ""),
                agent_name=self.name,
                detail=detail,
            ))

    # -- blackboard integration ---------------------------------------------

    def _write_to_blackboard(self, ctx: AgentContext, finding: Finding) -> None:
        """Write a finding to the blackboard if available."""
        if self.blackboard and ctx:
            from core.blackboard import Finding as BlackboardFinding, FindingType
            
            # Convert memory Finding to blackboard Finding
            bf = BlackboardFinding(
                campaign_id=ctx.options.get("campaign_id", ""),
                agent_name=self.name,
                type=FindingType.RECON,  # Default, can be mapped
                target=ctx.target,
                data=json.dumps(finding.to_dict()).encode(),
                pheromone_base=1.0,
            )
            self.blackboard.write(bf)

    # -- skill execution ----------------------------------------------------

    def _execute_skill_from_decision(self, ctx: AgentContext, decision: Any) -> dict[str, Any]:
        """Execute a skill based on LLM decision."""
        skill_name = getattr(decision, 'skill', '')
        skill_params = getattr(decision, 'params', {})
        
        # Find the skill
        skill = None
        for s in self.skills:
            if s.name == skill_name:
                skill = s
                break
        
        if not skill:
            return {"status": "error", "message": f"Skill '{skill_name}' not found"}
        
        # Emit skill executed event
        self._emit_event(EventType.SKILL_EXECUTED, ctx, detail=f"Skill: {skill_name}")
        
        # Execute the skill
        import asyncio
        try:
            context_dict: dict[str, Any] = {
                "target": ctx.target,
                "findings": [f.to_dict() for f in ctx.findings] if ctx.findings and hasattr(ctx.findings[0], 'to_dict') else [],
                "options": ctx.options,
            }
            result = asyncio.run(skill.execute(context_dict, **skill_params))
            return {"status": "success", "result": result}
        except Exception as exc:
            logger.error("Skill execution failed: %s", exc, exc_info=True)
            return {"status": "error", "message": str(exc)}

    # -- LLM interaction ---------------------------------------------------

    def _ask_llm(
        self,
        system: str,
        conversation: list[dict[str, str]],
        ctx: AgentContext | None = None,
    ) -> str:
        """Send the conversation to the LLM and return the response."""
        if self.llm is None or getattr(self.llm, "is_offline", False):
            return self._offline_response(conversation, ctx)

        try:
            prompt = "\n\n".join(
                f"[{m['role'].upper()}]\n{m['content']}" for m in conversation
            )
            return self.llm.complete(prompt, system=system)
        except Exception:
            logger.exception("LLM request failed; using offline fallback")
            return self._offline_response(conversation, ctx)

    def _offline_response(
        self,
        conversation: list[dict[str, str]],
        ctx: AgentContext | None = None,
    ) -> str:
        """Offline fallback — return a valid JSON decision for testing.

        On the first call it returns a ``run_command`` decision so the
        agent actually executes a tool. On subsequent calls (after command
        output has been fed back) it returns ``done`` so the loop terminates.

        If the last user message is an evasion request (a command was
        blocked), it applies a basic evasion flag to the command instead
        of stopping — this makes self-healing work even without an LLM.
        """
        # If we have an LLM configured, use it instead of offline mode
        if hasattr(self, 'llm') and self.llm is not None and not getattr(self.llm, 'is_offline', False):
            # This shouldn't happen, but if it does, return a safe response
            return json.dumps({
                "action": "done",
                "summary": "LLM available but offline response called."
            })
        
        # Otherwise, use the original offline logic
        target = self._extract_target(conversation)
        user_msgs = [m for m in conversation if m["role"] == "user"]
        target = self._extract_target(conversation)
        user_msgs = [m for m in conversation if m["role"] == "user"]

        # Check if the last user message is an evasion request.
        last_user = user_msgs[-1]["content"] if user_msgs else ""
        try:
            last_data = json.loads(last_user)
            if last_data.get("type") == "evasion_request":
                blocked_cmd = last_data.get("command", "")
                evaded = self._apply_evasion(
                    blocked_cmd,
                    ctx=ctx,
                    error=last_data.get("stderr", "") or last_data.get("stdout", ""),
                )

                # Count how many evasion attempts have been made. If the
                # evaded command is unchanged (no new flag could be applied)
                # or we've already tried evasion twice, stop to avoid an
                # infinite retry loop.
                evasion_attempts = sum(
                    1
                    for m in conversation
                    if m["role"] == "user"
                    and "evasion_request" in m["content"]
                )
                if evaded == blocked_cmd or evasion_attempts >= 2:
                    logger.warning(
                        "%s evasion exhausted for blocked command: %s",
                        self.name,
                        blocked_cmd,
                    )
                    return json.dumps({
                        "action": "done",
                        "summary": (
                            f"Offline mode: command '{blocked_cmd}' is blocked "
                            f"and evasion is exhausted on {target}."
                        ),
                    })

                logger.info(
                    "%s applying evasion to blocked command: %s -> %s",
                    self.name,
                    blocked_cmd,
                    evaded,
                )
                return json.dumps({
                    "action": "run_command",
                    "command": evaded,
                    "reasoning": "Offline evasion: applying stealth flag to bypass block.",
                })
        except (json.JSONDecodeError, ValueError):
            pass

        if len(user_msgs) > 1:
            return json.dumps({
                "action": "done",
                "summary": f"Offline mode: completed scan of {target}.",
            })
        return json.dumps({
            "action": "run_command",
            "command": self._offline_command(target),
            "reasoning": "Offline mode: performing scan.",
        })

    def _offline_command(self, target: str) -> str:
        """Return the offline command for this agent type."""
        return f"nmap -sV -T4 --top-ports 100 {target}"

    @staticmethod
    def _extract_target(conversation: list[dict[str, str]]) -> str:
        """Extract the target from the conversation's user messages."""
        for msg in reversed(conversation):
            if msg["role"] == "user":
                match = re.search(r"Target:\s*(\S+)", msg["content"])
                if match:
                    return match.group(1)
        return "127.0.0.1"

    # -- web search & OSINT ------------------------------------------------

    @staticmethod
    def web_search(query: str, *, max_results: int = 5, timeout: int = 10) -> list[dict[str, str]]:
        """Search the web for CVEs / exploits related to a query.

        Uses DuckDuckGo's HTML endpoint (no API key required) and parses
        results with BeautifulSoup. Returns a list of {title, url, snippet}.
        """
        import requests
        from bs4 import BeautifulSoup

        results: list[dict[str, str]] = []
        try:
            resp = requests.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            for result in soup.select(".result")[:max_results]:
                link = result.select_one(".result__a")
                snippet = result.select_one(".result__snippet")
                if link:
                    results.append({
                        "title": str(link.get_text(strip=True)),
                        "url": str(link.get("href", "") or ""),
                        "snippet": str(snippet.get_text(strip=True)) if snippet else "",
                    })
        except Exception:
            logger.exception("web_search failed for query: %s", query)
        return results

    def search_cve(self, product: str, version: str = "") -> list[dict[str, str]]:
        """Search for known CVEs / exploits for a product+version."""
        query = f"{product} {version} CVE exploit".strip()
        return self.web_search(query)

    def _build_web_search_prompt(self, product: str, version: str = "") -> str:
        """Build a prompt asking the LLM to use web_search for a product."""
        return json.dumps({
            "type": "web_search_request",
            "product": product,
            "version": version,
            "instruction": (
                f"Search the web for known CVEs and exploits for {product} {version}. "
                "Use the web_search tool. Then decide whether to use searchsploit "
                "or craft a custom payload. Respond with JSON only."
            )
        })

    # -- auto-evasion (self-healing) ---------------------------------------

    # Keywords that indicate a command was blocked, rate-limited, or failed.
    BLOCKED_KEYWORDS: tuple[str, ...] = (
        "blocked",
        "timeout",
        "timed out",
        "waf",
        "rate limit",
        "rate-limited",
        "connection refused",
        "connection reset",
        "access denied",
        "forbidden",
        "403",
        "429",
        "too many requests",
        "captcha",
        "challenge",
        "denied",
        "refused",
        "unreachable",
        "no route to host",
        "permission denied",
        "not recognized",
        "is not recognized",
        "command not found",
        "failed",
    )

    @classmethod
    def _detect_blocked(cls, stdout: str, stderr: str, rc: int) -> bool:
        """Detect if a command output indicates it was blocked or failed.

        Returns True if the output contains any evasion-triggering keyword
        or the return code indicates a hard failure (e.g. tool not found).
        """
        combined = f"{stdout} {stderr}".lower()
        for kw in cls.BLOCKED_KEYWORDS:
            if kw in combined:
                return True
        # rc == -3 means the tool itself failed to launch (not found, etc.)
        if rc == -3:
            return True
        return False

    def _build_evasion_prompt(
        self, command: str, stdout: str, stderr: str, rc: int
    ) -> str:
        """Build a prompt asking the LLM to suggest an evasion strategy.

        The LLM is asked to analyze the failure and propose an alternative
        tool or an evasion flag (e.g. --random-agent, -T2, masscan instead
        of nmap). The response must be strict JSON.
        """
        return json.dumps({
            "type": "evasion_request",
            "command": command,
            "return_code": rc,
            "stdout": (stdout or "")[:1000],
            "stderr": (stderr or "")[:1000],
            "instruction": (
                "The command appears to have been blocked or failed. "
                "Analyze the error and suggest an alternative tool or an "
                "evasion flag (e.g. --random-agent, -T2, use masscan instead "
                "of nmap, add a delay, rotate User-Agent, etc.). "
                "Respond with JSON only: "
                '{"action": "run_command", "command": "your alternative command", '
                '"reasoning": "why this evades the block"} '
                "or {\"action\": \"done\", \"summary\": \"...\"} if you cannot proceed."
            )
        })

    def _apply_evasion(
        self,
        command: str,
        *,
        ctx: AgentContext | None = None,
        error: str = "",
    ) -> str:
        """Apply an intelligent evasion technique.

        Strategy (in order):
        1. Query the RAG system for a past evasion technique that worked
           against a similar error / WAF.
        2. If found, reuse that technique (learned from experience).
        3. Otherwise, apply a heuristic evasion flag based on the tool.
        4. Record the applied technique in RAG for future use.
        """
        # 1. Try RAG-based evasion (learned from past experience).
        if ctx is not None and ctx.memory is not None:
            past = ctx.memory.rag.find_evasion_for(error or command)
            if past:
                logger.info(
                    "%s reusing RAG evasion technique: %s",
                    self.name,
                    past[:120],
                )
                # Extract the actual command from the stored technique.
                extracted = self._extract_command_from_text(past)
                if extracted:
                    return extracted
                # If we can't extract a valid command, fall back to heuristic evasion
                # instead of returning the raw text (which would cause a command error)
                logger.warning(
                    "%s could not extract command from RAG technique, using heuristic",
                    self.name,
                )

        # 2. Heuristic evasion based on the tool.
        evaded = self._heuristic_evasion(command)

        # 3. Record the applied technique in RAG for future use.
        if ctx is not None and ctx.memory is not None and evaded != command:
            ctx.memory.rag.record_evasion(
                f"Command: {evaded}",
                target=ctx.target,
                agent=self.name,
                waf=error or "unknown",
                success=True,
            )
            logger.info(
                "%s recorded evasion technique in RAG: %s",
                self.name,
                evaded[:120],
            )

        return evaded

    @staticmethod
    def _extract_command_from_text(text: str) -> str | None:
        """Extract an executable command from stored technique text."""
        # Format: "Command: nmap -sV -T2 target"
        if "Command:" in text:
            return text.split("Command:")[1].split("\n")[0].strip()
        # Format: "Evasion technique: nmap -T2 to evade rate limit"
        if "Evasion technique: " in text:
            candidate = text.split("Evasion technique:")[1].split("\n")[0].strip()
            # Strip trailing explanation words that are not part of the command.
            for word in (" to ", " for ", " against ", " bypass "):
                idx = candidate.find(word)
                if idx > 0:
                    candidate = candidate[:idx]
            # Extract only the command part (first line, before any explanation)
            candidate = candidate.split()[0] if candidate else ""
            return candidate.strip() or None
        # If no clear format, try to extract first word as command
        return text.split()[0] if text else None

    @staticmethod
    def _heuristic_evasion(command: str) -> str:
        """Apply a basic evasion flag to a command as a fallback.

        Adds a timing/stealth flag where appropriate.
        """
        # nmap: slow down timing to evade rate limits / WAFs.
        if command.startswith("nmap"):
            if "-T" not in command:
                return f"{command} -T2"
        # curl: add a random User-Agent to evade WAF fingerprinting.
        elif command.startswith("curl"):
            if "--random-agent" not in command and "-A" not in command:
                return f"{command} --random-agent"
        # masscan: slow down the rate.
        elif command.startswith("masscan"):
            if "--rate" not in command:
                return f"{command} --rate=100"
        # nuclei: add a delay between requests.
        elif command.startswith("nuclei"):
            if "-rl" not in command and "-rate-limit" not in command:
                return f"{command} -rl 10"
        # sqlmap: add a delay and random agent.
        elif command.startswith("sqlmap"):
            if "--delay" not in command:
                return f"{command} --delay=2 --random-agent"
        return command

    @staticmethod
    def _is_url(target: str) -> bool:
        """Check if a target looks like a URL."""
        return target.startswith(("http://", "https://"))

    @staticmethod
    def _host_from_target(target: str) -> str:
        """Extract the host from a URL target."""
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.hostname or target
        return target

    # -- observation formatting --------------------------------------------

    @staticmethod
    def _format_observation(cmd: str, rc: int, stdout: str, stderr: str) -> str:
        """Format command output as JSON for the LLM."""
        return json.dumps({
            "type": "command_output",
            "command": cmd,
            "return_code": rc,
            "stdout": stdout[:2000] if stdout else "",
            "stderr": stderr[:1000] if stderr else "",
            "instruction": "Analyze the output. Respond with JSON: run_command, done, or finding."
        })

    # -- finding helpers ---------------------------------------------------

    def _finding_from_command(
        self, target: str, cmd: str, rc: int, stdout: str, stderr: str
    ) -> Finding | None:
        """Create a finding from a command execution."""
        if not stdout and not stderr:
            return None
        return self.make_finding(
            agent_name=self.name,
            finding_type="recon",
            target=target,
            severity="info",
            description=f"Command executed: {cmd}",
            evidence=(stdout or stderr)[:500],
            confidence=0.7,
            metadata={"command": cmd, "return_code": rc},
        )

    @staticmethod
    def make_finding(
        *,
        agent_name: str,
        finding_type: str = "info",
        target: str = "",
        severity: str = "info",
        description: str = "",
        evidence: str = "",
        confidence: float = 0.5,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Convenience factory for creating a :class:`Finding`."""
        return Finding(
            agent_name=agent_name,
            finding_type=finding_type,
            target=target,
            severity=severity,
            description=description,
            evidence=evidence,
            confidence=confidence,
            metadata=metadata or {},
        )

    # -- memory helpers ---------------------------------------------------

    def recall_memory(self, ctx: AgentContext, keywords: list[str]) -> list[MemoryEntry]:
        """Consult the memory store for relevant past findings."""
        if ctx.memory is None:
            return []
        return ctx.memory.recall_relevant(keywords)

    def record_to_memory(self, ctx: AgentContext, finding: Finding) -> None:
        """Record a finding to the shared memory store."""
        if ctx.memory is not None:
            ctx.memory.record_finding(finding)

    def publish_to_queue(self, ctx: AgentContext, finding: Finding) -> None:
        """Publish a finding to the async memory queue (stigmergy)."""
        if ctx.queue is not None:
            ctx.queue.publish(finding)

    def _build_context_from_findings(self, findings: list[Finding]) -> str:
        """Build a JSON summary of previous findings for the LLM prompt."""
        if not findings:
            return "none"
        items: list[dict[str, Any]] = []
        for f in findings:
            items.append({
                "type": f.finding_type,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence[:100] if f.evidence else "",
                "confidence": f.confidence,
                "agent": f.agent_name,
            })
        return json.dumps(items)

    # -- subprocess --------------------------------------------------------

    @staticmethod
    def run_tool(
        command: str,
        *,
        timeout: int = 120,
        check: bool = False,
    ) -> tuple[int, str, str]:
        """Run a shell command and return (returncode, stdout, stderr)."""
        logger.debug("running: %s", command)
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -2, "", f"timeout after {timeout}s: {command}"
        except Exception as exc:
            return -3, "", str(exc)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"