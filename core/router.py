"""Command router — distributes tasks to the right agent.

Inspired by OmniRoute's routing philosophy: instead of a single monolithic
pipeline, the router inspects an incoming command / target and decides
which swarm agent(s) are best suited to handle it. Routing can be
rule-based (fast path) or LLM-assisted (when the intent is ambiguous).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("zahra.core.router")


class Intent(str, Enum):
    """High-level intent categories the router can classify."""

    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    C2 = "c2"
    MITM = "mitm"
    FULL = "full"  # full chain: recon → scan → exploit
    UNKNOWN = "unknown"


@dataclass
class RouteDecision:
    """The outcome of routing a command.

    Attributes:
        intent: Classified intent.
        agents: Ordered list of agent names to invoke.
        target: Normalized target (host, IP, URL).
        options: Extra options forwarded to agents.
        reasoning: Human-readable explanation of the routing decision.
    """

    intent: Intent = Intent.UNKNOWN
    agents: list[str] = field(default_factory=list)
    target: str = ""
    options: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


# ---------------------------------------------------------------------------
# Rule-based router
# ---------------------------------------------------------------------------

# Keyword → intent mapping for the fast path.
_KEYWORD_MAP: dict[Intent, list[str]] = {
    Intent.RECON: [
        "recon",
        "reconnaissance",
        "enumerate",
        "discover",
        "whois",
        "subdomain",
        "dns",
        "osint",
    ],
    Intent.SCAN: [
        "scan",
        "nmap",
        "port",
        "vuln",
        "nuclei",
        "nikto",
        "fingerprint",
        "service",
    ],
    Intent.EXPLOIT: [
        "exploit",
        "attack",
        "penetrate",
        "break",
        "shell",
        "payload",
        "metasploit",
        "sqli",
        "xss",
        "rce",
    ],
    Intent.C2: [
        "c2",
        "command and control",
        "command-and-control",
        "c&c",
        "beacon",
        "implant",
        "listener",
        "payload delivery",
    ],
    Intent.MITM: [
        "mitm",
        "man in the middle",
        "man-in-the-middle",
        "intercept",
        "sniff",
        "arp spoof",
        "arp-spoof",
        "dns spoof",
        "session hijack",
    ],
    Intent.FULL: [
        "full",
        "all",
        "complete",
        "chain",
        "pentest",
        "assessment",
        "audit",
    ],
}

# Regex to extract a target (host, IP, or URL) from free text.
_TARGET_PATTERNS = [
    re.compile(r"https?://[^\s,]+", re.IGNORECASE),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),  # IPv4
    re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),  # domain
]


class Router:
    """Routes incoming commands to the appropriate swarm agents.

    The router uses a two-tier strategy:

    1. **Fast path** — keyword matching against a rule table. Handles the
       common, unambiguous cases without spending LLM tokens.
    2. **Smart path** — delegates to the AI engine's decision maker when
       the fast path is ambiguous. This is optional and only used when an
       LLM wrapper is configured.
    """

    def __init__(self, llm_wrapper: Any | None = None) -> None:
        self._llm = llm_wrapper
        self._keyword_map = {kw: intent for intent, kws in _KEYWORD_MAP.items() for kw in kws}

    # -- public API --------------------------------------------------------

    def route(self, command: str, *, default_intent: Intent = Intent.FULL) -> RouteDecision:
        """Classify *command* and produce a :class:`RouteDecision`."""
        command_lower = command.lower().strip()
        target = self._extract_target(command)
        intent = self._classify(command_lower, default_intent)
        agents = self._agents_for_intent(intent)
        reasoning = self._explain(intent, target, command_lower)

        # If the fast path is uncertain, try the smart path.
        if intent == Intent.UNKNOWN and self._llm is not None:
            smart = self._smart_route(command)
            if smart is not None:
                intent = smart
                agents = self._agents_for_intent(intent)
                reasoning = f"LLM-assisted routing → {intent.value}. {reasoning}"

        return RouteDecision(
            intent=intent,
            agents=agents,
            target=target,
            reasoning=reasoning,
        )

    # -- classification ----------------------------------------------------

    def _classify(self, text: str, default: Intent) -> Intent:
        for keyword, intent in self._keyword_map.items():
            if keyword in text:
                return intent
        return default

    def _smart_route(self, command: str) -> Intent | None:
        """Use the LLM to classify an ambiguous command."""
        if self._llm is None:
            return None
        try:
            prompt = (
                "Classify the following security command into exactly one of: "
                "recon, scan, exploit, full. "
                "Reply with only the single word.\n\n"
                f"Command: {command}"
            )
            response = self._llm.complete(prompt)
            label = response.strip().lower()
            for intent in Intent:
                if intent.value in label:
                    return intent
        except Exception:
            logger.exception("smart routing failed")
        return None

    # -- target extraction -------------------------------------------------

    @staticmethod
    def _extract_target(text: str) -> str:
        for pattern in _TARGET_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0).rstrip(".,;:)]")
        return ""

    # -- agent mapping -----------------------------------------------------

    @staticmethod
    def _agents_for_intent(intent: Intent) -> list[str]:
        mapping: dict[Intent, list[str]] = {
            Intent.RECON: ["recon_agent"],
            Intent.SCAN: ["scan_agent"],
            Intent.EXPLOIT: ["exploit_agent"],
            Intent.C2: ["c2_agent"],
            Intent.MITM: ["mitm_agent"],
            Intent.FULL: ["recon_agent", "scan_agent", "exploit_agent", "c2_agent", "mitm_agent"],
            Intent.UNKNOWN: ["recon_agent", "scan_agent"],
        }
        return mapping.get(intent, ["recon_agent", "scan_agent"])

    @staticmethod
    def _explain(intent: Intent, target: str, text: str) -> str:
        if intent == Intent.UNKNOWN:
            return f"Could not classify intent from '{text}'; defaulting to recon+scan."
        if target:
            return f"Routed to {intent.value} for target {target}."
        return f"Routed to {intent.value} (no explicit target detected)."