"""Retriever — semantic search interface for the Adaptive RAG system.

Agents use this to ask "have I seen this situation before?" and get back
relevant past experiences (findings, commands, evasions) to inform their
next action.
"""

from __future__ import annotations

import logging
from typing import Any

from core.rag_system.vector_store import RAGVectorStore

logger = logging.getLogger("zahra.rag.retriever")


class RAGRetriever:
    """High-level semantic retrieval for agents."""

    def __init__(self, store: RAGVectorStore | None = None) -> None:
        self.store = store or RAGVectorStore()

    # -- context building --------------------------------------------------

    def build_context(
        self,
        query: str,
        *,
        n: int = 5,
        include_findings: bool = True,
        include_commands: bool = True,
        include_evasions: bool = True,
    ) -> str:
        """Build a human-readable context string from RAG search results.

        This is injected into the LLM prompt so the agent can leverage
        past experience when planning its next command.
        """
        if not self.store.available:
            return ""

        parts: list[str] = []
        if include_findings:
            findings = self.store.search_findings(query, n=n)
            if findings:
                parts.append("### Past findings (from RAG memory):")
                for f in findings:
                    meta = f.get("metadata", {})
                    parts.append(
                        f"- [{meta.get('severity', 'info')}] {f.get('text', '')[:200]} "
                        f"(target: {meta.get('target', '?')}, agent: {meta.get('agent', '?')})"
                    )

        if include_commands:
            commands = self.store.search_commands(query, n=n)
            if commands:
                parts.append("### Past commands (from RAG memory):")
                for c in commands:
                    meta = c.get("metadata", {})
                    outcome = meta.get("outcome", "?")
                    parts.append(
                        f"- [{outcome}] {c.get('text', '')[:200]} "
                        f"(target: {meta.get('target', '?')})"
                    )

        if include_evasions:
            evasions = self.store.search_evasions(query, n=n)
            if evasions:
                parts.append("### Past evasion techniques (from RAG memory):")
                for e in evasions:
                    meta = e.get("metadata", {})
                    waf = meta.get("waf", "?")
                    parts.append(
                        f"- {e.get('text', '')[:200]} (WAF: {waf})"
                    )

        return "\n".join(parts)

    # -- targeted lookups --------------------------------------------------

    def find_evasion_for(self, error: str, waf: str = "") -> str | None:
        """Find a past evasion technique that worked against a similar error/WAF."""
        query = f"evasion technique for {error} {waf}".strip()
        results = self.store.search_evasions(query, n=3)
        for r in results:
            meta = r.get("metadata", {})
            if meta.get("success", True):
                return r.get("text", "")
        return None

    def find_successful_command(self, intent: str, target: str = "") -> str | None:
        """Find a past successful command for a similar intent/target."""
        query = f"{intent} {target}".strip()
        results = self.store.search_commands(query, n=3)
        for r in results:
            meta = r.get("metadata", {})
            if meta.get("success", False):
                text = r.get("text", "")
                # Extract the command line from "Command: <cmd>\nOutput: ..."
                if text.startswith("Command: "):
                    return text.split("\n")[0].replace("Command: ", "").strip()
        return None

    # -- recording ---------------------------------------------------------

    def record_finding(
        self,
        text: str,
        *,
        target: str = "",
        agent: str = "",
        severity: str = "info",
        finding_type: str = "info",
    ) -> None:
        self.store.add_finding(
            text, target=target, agent=agent, severity=severity, finding_type=finding_type
        )

    def record_command(
        self,
        command: str,
        *,
        target: str = "",
        agent: str = "",
        success: bool = True,
        output: str = "",
    ) -> None:
        self.store.add_command(
            command, target=target, agent=agent, success=success, output=output
        )

    def record_evasion(
        self,
        technique: str,
        *,
        target: str = "",
        agent: str = "",
        waf: str = "",
        success: bool = True,
    ) -> None:
        self.store.add_evasion(
            technique, target=target, agent=agent, waf=waf, success=success
        )

    # -- stats -------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        return self.store.summary()