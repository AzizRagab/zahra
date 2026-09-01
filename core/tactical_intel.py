"""Tactical intel layer — bridges Web Search, Adaptive RAG, and the trained model
into the agent decision loop.

This module exists so every agent (recon, scan, exploit, c2) gets:
1. Web intelligence from the multi-engine search stack (Bing RSS primary)
2. Semantic recall from the adaptive RAG store (hybrid embedding + TF-IDF)
3. Trained-model context injection from `zahra-finetuned`

It deliberately keeps dependencies lazy so the swarm works even when
Ollama / web is unavailable (offline-tolerant by design).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("zahra.intel")

try:
    from ai_agent.web_search import WebSearch
except Exception:  # pragma: no cover - optional import
    WebSearch = None

try:
    from ai_agent.adaptive_rag import AdaptiveRAG
except Exception:  # pragma: no cover - optional import
    AdaptiveRAG = None


@dataclass
class IntelResult:
    """A unified intel snapshot returned to an agent."""

    source: str
    query: str
    ok: bool = True
    data: Any = None
    error: str = ""
    cached: bool = False
    relevance: float = 1.0
    latency: float = 0.0
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "query": self.query,
            "ok": self.ok,
            "data": self.data,
            "error": self.error,
            "cached": self.cached,
            "relevance": self.relevance,
            "latency": self.latency,
            "ts": self.ts,
        }


class TacticalIntel:
    """Tactical intelligence service worn by every agent.

    Responsibilities:
      * Web OSINT (Bing RSS + fallbacks) with cold/hot caching
      * RAG recall for knowledge-base questions (CVE lookups, technique names)
      * Fusion: combine web hits + semantic snippets into one context bundle
      * Decision-logging (gstack decision-log style) for audit trail
    """

    _instance: "TacticalIntel | None" = None
    _lock = threading.Lock()

    def __init__(self, *, rag: Any = None, searcher: Any = None) -> None:
        self._searcher = searcher
        self._rag = rag
        self._cache: dict[str, tuple[float, Any]] = {}
        self._cache_ttl = int(os.environ.get("ZAHRA_INTEL_CACHE_TTL", "180"))
        self._max_cache = int(os.environ.get("ZAHRA_INTEL_CACHE_MAX", "512"))
        if self._searcher is None and WebSearch is not None:
            try:
                self._searcher = WebSearch()
            except Exception as exc:  # pragma: no cover
                logger.warning("WebSearchEngine init failed: %s", exc)
        if self._rag is None and AdaptiveRAG is not None:
            try:
                self._rag = AdaptiveRAG()
            except Exception as exc:  # pragma: no cover
                logger.warning("AdaptiveRAG init failed: %s", exc)

    # -- web -----------------------------------------------------------------

    def web_intel(self, query: str, *, timeout: int = 25) -> IntelResult:
        """Search the web for a query, returning top hits with relevance."""
        cache_key = f"web:{query.strip().lower()}"
        hit = self._cache_get(cache_key)
        if hit is not None:
            return IntelResult(source="web-cache", query=query, data=hit, cached=True)

        if self._searcher is None:
            return IntelResult(source="web", query=query, ok=False, error="no searcher configured")

        start = time.monotonic()
        try:
            results = self._searcher.search(query, timeout=timeout)
            self._cache_put(cache_key, results)
            return IntelResult(
                source="web",
                query=query,
                data=results,
                relevance=1.0 if results else 0.0,
                latency=round(time.monotonic() - start, 3),
            )
        except Exception as exc:  # pragma: no cover
            return IntelResult(source="web", query=query, ok=False, error=str(exc))

    # -- semantic knowledge ---------------------------------------------------

    def knowledge_recall(self, query: str, top_k: int = 5) -> IntelResult:
        """Recall relevant knowledge (CVE info, techniques, how-tos) from RAG.

        Uses the AdaptiveRAG.recall(limit=...) API internally.
        """
        cache_key = f"rag:{query.lower()}"
        hit = self._cache_get(cache_key)
        if hit is not None:
            return IntelResult(source="rag-cache", query=query, data=hit, cached=True)

        if self._rag is None:
            return IntelResult(source="rag", query=query, ok=False, error="rag unavailable")

        start = time.monotonic()
        try:
            # AdaptiveRAG.recall accepts limit (default 50), we map top_k -> limit
            docs = self._rag.recall(limit=max(top_k, 1))
            self._cache_put(cache_key, docs)
            return IntelResult(
                source="rag",
                query=query,
                data=docs,
                relevance=1.0 if docs else 0.0,
                latency=round(time.monotonic() - start, 3),
            )
        except Exception as exc:  # pragma: no cover
            return IntelResult(source="rag", query=query, ok=False, error=str(exc))

    # -- fusion -------------------------------------------------------------------

    def fused_context(self, query: str, *, include_web: bool = True, top_k: int = 4) -> str:
        """Return a compact markdown context bundle (web + semantic)."""
        parts: list[str] = []
        rag = self.knowledge_recall(query, top_k=top_k)
        if rag.relevance and rag.data:
            parts.append("### Knowledge (RAG)")
            for i, doc in enumerate(rag.data[:top_k], 1):
                snippet = doc.get("text") or doc.get("content") or str(doc)
                parts.append(f"{i}. {snippet[:500]}")
        if include_web:
            web = self.web_intel(query)
            if web.relevance and web.data:
                parts.append("### Web intel")
                for i, hit in enumerate(web.data[:4], 1):
                    title = hit.get("title") or hit.get("name") or "?"
                    link = hit.get("url") or hit.get("link") or ""
                    parts.append(f"{i}. **{title}** — {link}")
        return "\n\n".join(parts)

    # -- audit trail (gstack decision-log style) --------------------------------

    def log_decision(self, skill: str, decision: str, reason: str, supersede: str | None = None) -> None:
        """Persist a durable decision for cross-session recall."""
        try:
            log_path = Path(os.environ.get("GSTACK_HOME", str(Path.home() / ".gstack")))
            log_path = log_path / "projects" / os.environ.get("ZAHRA_SLUG", "zahra") / "decisions.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": time.time(),
                "skill": skill,
                "decision": decision,
                "reason": reason,
                "supersedes": supersede,
            }
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
        except Exception as exc:  # pragma: no cover
            logger.debug("decision log failed: %s", exc)

    # -- helpers ----------------------------------------------------------------------

    def _cache_get(self, key: str) -> Any | None:
        item = self._cache.get(key)
        if item is None:
            return None
        ts, value = item
        if time.time() - ts > self._cache_ttl:
            self._cache.pop(key, None)
            return None
        return value

    def _cache_put(self, key: str, value: Any) -> None:
        if len(self._cache) >= self._max_cache:
            oldest = min(self._cache, key=lambda k: self._cache[k][0], default=None)
            if oldest is not None:
                self._cache.pop(oldest, None)
        self._cache[key] = (time.time(), value)

    @classmethod
    def get(cls) -> "TacticalIntel":
        """Global single instance (shared across agents)."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance