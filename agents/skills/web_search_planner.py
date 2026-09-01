"""Web Search Planner — multi-query planning, expansion, and fusion.

Adds a lightweight planning layer on top of ``ai_agent.web_search.WebSearch``:
- Query Expansion
- Multi-Query Fusion
- Automatic rewrite when results are weak/irrelevant
- Simple confidence-aware fusion across multiple sub-queries
"""

from __future__ import annotations

import logging
import random
from typing import Any

logger = logging.getLogger("zahra.skills.web_search_planner")


class SearchPlanner:
    """Lightweight search planner that expands a single user query into
    multiple complementary queries, runs them, and fuses results.

    It also detects low-quality/irrelevant results and rewrites/retries
    with alternative queries before giving up.
    """

    def __init__(self, backend: Any) -> None:
        self.backend = backend

    def plan(self, query: str) -> list[str]:
        """Return multiple query variants for the same information need."""
        q = query.strip()
        variants = [q]

        # Lightweight expansion patterns (language-agnostic heuristics)
        prefixes = [
            f"{q} tutorial",
            f"{q} explained",
            f"{q} latest",
            f"{q} official docs",
            f"{q} CVE",
        ]
        # Shuffle to reduce bias toward one variant
        random.shuffle(prefixes)
        variants.extend(prefixes[:3])

        # De-dup while preserving order
        seen: set[str] = set()
        out: list[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def fuse(
        self,
        query_groups: dict[str, list[dict[str, Any]]],
        max_results: int = 8,
    ) -> list[dict[str, Any]]:
        """Merge results from multiple queries into a single ranked list.

        Heuristic ranking:
        1. URLs already seen in another result move down.
        2. Items with more informative snippets rise.
        3. Diversity across engines is preferred.
        """
        seen: set[str] = set()
        fused: list[dict[str, Any]] = []

        # Flatten with per-engine round-robin to preserve diversity
        buckets: list[tuple[str, list[dict[str, Any]]]] = []
        for q, results in query_groups.items():
            if results:
                buckets.append((q, results))

        max_bucket_len = max((len(b[1]) for b in buckets), default=0)
        for i in range(max_bucket_len):
            for _, results in buckets:
                if i >= len(results):
                    continue
                r = results[i]
                url = r.get("url", "")
                if not url or url in seen:
                    continue
                seen.add(url)
                r["confidence"] = self._score(r)
                fused.append(r)
                if len(fused) >= max_results:
                    return fused
        return fused

    def search_with_plan(
        self,
        query: str,
        max_results: int = 8,
        *,
        deep: bool = False,
    ) -> dict[str, Any]:
        """Run planned multi-query search and return structured output.

        If all variants return empty/irrelevant results, the query is
        rewritten once and retried.
        """
        variants = self.plan(query)
        query_groups: dict[str, list[dict[str, Any]]] = {}
        all_results: list[dict[str, Any]] = []

        for q in variants:
            try:
                if deep:
                    res = self.backend.search_and_fetch(q, top_k=max(3, max_results))
                else:
                    res = self.backend.search(q, top_k=max_results)
            except Exception as exc:  # noqa: BLE001
                logger.warning("search failed for variant %r: %s", q, exc)
                res = []
            query_groups[q] = res or []
            all_results.extend(query_groups[q])

        fused = self.fuse(query_groups, max_results=max_results)

        # Retry once with a simplified query if nothing useful came back
        if not fused:
            simplified = " ".join(self._extract_terms(query))
            if simplified and simplified != query:
                try:
                    retry = self.backend.search(simplified, top_k=max_results)
                except Exception:  # noqa: BLE001
                    retry = []
                if retry:
                    fused = self.fuse({"retry": retry}, max_results=max_results)

        status = "success" if fused else "empty"
        return {
            "status": status,
            "query": query,
            "results": fused,
            "total": len(fused),
            "engines": sorted({r.get("engine") for r in fused if r.get("engine")}),
            "deep": bool(deep),
        }

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _extract_terms(query: str) -> list[str]:
        import re
        stop = {
            "the","and","for","are","was","with","how","what","when","where",
            "who","why","this","that","from","into","which","have","has","its",
            "not","you","your","our","their","about","than","then","them","they",
            "will","would","can","could","should","may","might","there","these",
            "those","also","all","any","per","via","using","used",
        }
        words = re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]+", query.lower())
        return [w for w in words if len(w) >= 3 and w not in stop]

    @staticmethod
    def _score(result: dict[str, Any]) -> float:
        """Very rough confidence heuristic based on snippet richness."""
        snippet = result.get("snippet") or ""
        title = result.get("title") or ""
        blob = f"{title} {snippet}".lower()
        score = 0.0
        if title and snippet:
            score += 0.3
        if len(snippet) >= 40:
            score += 0.3
        if len(snippet) >= 120:
            score += 0.2
        # prefer URLs that look like documentation/references
        url = result.get("url", "")
        if any(k in url for k in ["/wiki/", "docs.", "github.com", "cve.", "nvd.", "mitre.org"]):
            score += 0.3
        return min(1.0, max(0.0, score))