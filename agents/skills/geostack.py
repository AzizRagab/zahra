"""GeoStack skill for the zahra system.

Provides AI-powered reasoning and research capabilities using the OmniRoute GeoStack
layer. Enables agents to summarize content, extract structured JSON, and synthesize
research from multiple sources using 90+ free AI providers.

This skill wraps the GeoStackChannel from the agent-reach library to provide
AI reasoning capabilities within the zahra framework.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseSkill
from agent_reach.channels.geostack import GeoStackChannel

logger = logging.getLogger("zahra.skills.geostack")


class GeoStackSkill(BaseSkill):
    """Skill for GeoStack AI-powered reasoning and research.

    Provides access to OmniRoute's GeoStack gateway which connects to 90+ free AI
    providers for:
    - Summarizing web pages
    - Extracting structured JSON from content
    - Synthesizing multi-source research
    - Translating and explaining code
    - Intelligent reasoning over internet content
    """

    def __init__(self) -> None:
        """Initialize the GeoStack skill."""
        super().__init__(
            name="geostack",
            description="AI-powered reasoning and research using OmniRoute GeoStack with 90+ free providers",
        )
        self._geostack = GeoStackChannel()

    async def execute(self, context: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Execute a GeoStack operation.

        Supported operations (via 'operation' kwarg):
        - summarize_url: Summarize a web page
        - extract_json: Extract structured JSON from a web page
        - synthesize_research: Synthesize research from multiple sources
        - chat: General chat completion

        Args:
            context: Execution context
            **kwargs: Operation-specific parameters:
                - operation (str): The operation to perform
                - url (str): URL for summarize_url/extract_json
                - schema (str): JSON schema for extract_json
                - sources (list): Source dicts for synthesize_research
                - question (str): Question for synthesize_research
                - messages (list): Messages for chat operation

        Returns:
            Operation result dict
        """
        operation = kwargs.get("operation", "chat")

        try:
            if operation == "summarize_url":
                url = kwargs.get("url", "")
                if not url:
                    return {"status": "error", "error": "URL required for summarize_url"}
                summary = self._geostack.summarize_url(url)
                return {"status": "success", "summary": summary, "url": url}

            elif operation == "extract_json":
                url = kwargs.get("url", "")
                schema = kwargs.get("schema", "")
                if not url:
                    return {"status": "error", "error": "URL required for extract_json"}
                result = self._geostack.extract_json(url, schema=schema)
                return {"status": "success", "result": result, "url": url, "schema": schema}

            elif operation == "synthesize_research":
                sources = kwargs.get("sources", [])
                question = kwargs.get("question", "")
                if not sources:
                    return {"status": "error", "error": "Sources required for synthesize_research"}
                result = self._geostack.synthesize_research(sources, question)
                return {"status": "success", "result": result, "question": question}

            elif operation == "chat":
                messages = kwargs.get("messages", [])
                if not messages:
                    return {"status": "error", "error": "Messages required for chat"}
                result = self._geostack.chat(messages)
                return {"status": "success", "result": result, "messages": messages}

            else:
                return {"status": "error", "error": f"Unknown operation: {operation}"}

        except Exception as exc:
            logger.exception("GeoStack operation failed")
            return {"status": "error", "error": str(exc)}

    def can_handle(self, task_type: str) -> bool:
        """Check if this skill can handle the task type."""
        return task_type in ["geostack", "ai_reasoning", "research", "summarize", "extract_json"]

    def get_capabilities(self) -> list[str]:
        """Return list of supported operations."""
        return ["summarize_url", "extract_json", "synthesize_research", "chat"]