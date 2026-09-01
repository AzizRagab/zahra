"""Web search skill for agents.

Provides real web search capabilities for OSINT and CVE discovery,
backed by the multi-engine ``WebSearch`` backend in
``ai_agent.web_search`` (Bing RSS -> Bing -> DuckDuckGo Lite ->
DuckDuckGo HTML -> Mojeek -> Google CSE).

This replaces the previous placeholder that returned empty results
with ``status: "simulated"``.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseSkill

logger = logging.getLogger("zahra.skills.web_search")


class WebSearchSkill(BaseSkill):
    """Skill for performing real web searches.

    Allows agents to search the web for:
    - CVE information
    - OSINT data
    - Technology fingerprints
    - Exploit techniques
    """

    def __init__(self) -> None:
        """Initialize the web search skill."""
        super().__init__(
            name="web_search",
            description="Search the web for CVE information, OSINT data, and exploit techniques",
        )
        # Real backend created lazily so importing the skill never fails
        # even if optional deps (requests/bs4) are missing at import time.
        self._backend: Any = None

    def _get_backend(self) -> Any:
        """Lazily build and cache the real WebSearch backend."""
        if self._backend is None:
            from ai_agent.web_search import WebSearch

            self._backend = WebSearch()
        return self._backend

    async def execute(self, context: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Execute a real web search with planning, grounding, and citations.

        Args:
            context: Execution context with optional 'query' key
            **kwargs: Optional keys:
                - query (str): the search query
                - max_results (int): number of results to return (default 8)
                - deep (bool): if True, also fetch content from top pages
                  via ``WebSearch.search_and_fetch`` (default False)
                - plan (bool): if True, use multi-query planning/fusion
                  (default True)
                - learn (bool): if True, persist query/result quality to RAG
                  (default True)

        Returns:
            JSON-ready dict with keys: status, query, results, citations
            (and optionally 'deep': True when deep reads are enabled).
        """
        query = kwargs.get("query") or (context.get("query") if context else "") or ""
        if not query or not str(query).strip():
            return {
                "status": "error",
                "query": "",
                "results": [],
                "citations": [],
                "error": "Query cannot be empty",
            }

        deep = bool(kwargs.get("deep", False))
        max_results = int(kwargs.get("max_results", 8))
        max_results = max(1, min(max_results, 20))
        use_plan = bool(kwargs.get("plan", True))
        learn = bool(kwargs.get("learn", True))

        backend = self._get_backend()
        logger.info("Web search: %s (deep=%s, plan=%s)", query, deep, use_plan)

        try:
            if use_plan:
                from agents.skills.web_search_planner import SearchPlanner
                planner = SearchPlanner(backend)
                result = planner.search_with_plan(query, max_results=max_results, deep=deep)
                results = result.get("results", [])
                status = result.get("status", "success" if results else "empty")
                engines = result.get("engines", [])
            else:
                if deep:
                    results = backend.search_and_fetch(query, top_k=max_results)
                else:
                    results = backend.search(query, top_k=max_results)
                status = "success" if results else "empty"
                engines = sorted({r.get("engine") for r in results if r.get("engine")})
        except Exception as exc:  # noqa: BLE001
            logger.exception("Web search failed: %s", query)
            return {
                "status": "error",
                "query": query,
                "results": [],
                "citations": [],
                "error": str(exc),
            }

        # Grounding + citations
        citations = []
        for r in results:
            citations.append({
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "snippet": r.get("snippet", "")[:300],
                "engine": r.get("engine", ""),
                "confidence": r.get("confidence", 0.0),
            })

        out = {
            "status": status,
            "query": query,
            "results": results or [],
            "citations": citations,
            "total": len(results or []),
            "engines": engines,
        }
        if deep:
            out["deep"] = True

        logger.info("Web search completed: %d results (deep=%s)", len(results or []), deep)

        # Continuous learning via RAG (best-effort, never fails the request)
        if learn:
            try:
                self._learn(query, results)
            except Exception:  # noqa: BLE001
                logger.debug("learning skipped due to error", exc_info=True)

        return out

    def can_handle(self, task_type: str) -> bool:
        """Check if this skill can handle the task type.

        Args:
            task_type: Type of task

        Returns:
            True for search-related tasks
        """
        return task_type in ["search", "web_search", "osint", "cve_lookup"]

    # -- learning -------------------------------------------------------------

    def _learn(self, query: str, results: list[dict[str, Any]]) -> None:
        """Persist search outcome to the RAG corpus for future improvement.

        Stores a compact JSON record:
        {
          "type": "web_search_outcome",
          "query": query,
          "results_count": len(results),
          "top_confidence": top confidence or 0.0,
          "timestamp": now
        }
        """
        if not results:
            return
        try:
            from ai_agent.adaptive_rag import AdaptiveRAG
            import os
            rag_path = os.path.join("zahra_data", "web_search_learning.json")
            rag = AdaptiveRAG(rag_path)
            top_conf = max((r.get("confidence", 0.0) for r in results), default=0.0)
            rag.store(
                f"web_search_outcome: {query} | results={len(results)} | confidence={top_conf:.2f}",
                {
                    "type": "web_search_outcome",
                    "query": query,
                    "results_count": len(results),
                    "top_confidence": top_conf,
                    "timestamp": __import__("time").time(),
                },
            )
        except Exception:  # noqa: BLE001
            logger.debug("web search learning skipped", exc_info=True)
