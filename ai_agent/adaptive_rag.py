"""Adaptive RAG — memory and learning system for the AI agent.

This module provides a lightweight RAG system that:
1. Stores knowledge chunks with metadata
2. Uses hybrid retrieval: vector embeddings (Ollama nomic-embed-text,
   local) + TF-IDF cosine similarity (dependency-free fallback)
3. Adapts by weighting recent and frequently-hit knowledge higher
4. Understands compound IDs (CVE-2021-44228, OWASP Top 10, etc.)
5. Persists to JSON for long-term memory
6. Uses ChromaDB when available (with explicit Ollama embeddings)
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("zahra.ai_agent.rag")

_OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
_EMBED_MODEL = os.environ.get("ZAHRA_EMBED_MODEL", "nomic-embed-text")
_COMPOUND_RE = re.compile(r"^[a-z]+(?:-\d+)+$", re.I)  # CVE-2021-44228 style


class _OllamaEmbedder:
    """Local semantic embeddings via Ollama. Optional — returns None offline."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._cache: dict[str, list[float]] = {}
        self._ok: bool | None = None

    def _ping(self) -> bool:
        if self._ok is not None:
            return self._ok
        try:
            r = self._session.get(f"{_OLLAMA_BASE}/api/tags", timeout=3)
            self._ok = r.status_code == 200
        except Exception:
            self._ok = False
        return self._ok

    def embed(self, texts: list[str]) -> list[list[float]] | None:
        if not self._ping():
            return None
        out: list[list[float]] = []
        todo = [t for t in texts if t not in self._cache]
        if todo:
            try:
                r = self._session.post(
                    f"{_OLLAMA_BASE}/api/embed",
                    json={"model": _EMBED_MODEL, "input": todo},
                    timeout=60,
                )
                if r.status_code == 200:
                    data = r.json()
                    vecs = data.get("embeddings")
                    if vecs is None:  # older API style
                        vecs = [data["embedding"]] if "embedding" in data else None
                    if vecs:
                        for t, v in zip(todo, vecs):
                            self._cache[t] = v
                else:
                    # single-text fallback for old Ollama
                    for t in todo:
                        rr = self._session.post(
                            f"{_OLLAMA_BASE}/api/embeddings",
                            json={"model": _EMBED_MODEL, "prompt": t},
                            timeout=60,
                        )
                        if rr.status_code == 200:
                            emb = rr.json().get("embedding")
                            if emb:
                                self._cache[t] = emb
            except Exception:
                logger.info("embedding server unavailable at %s — falling back to TF-IDF", _OLLAMA_BASE)
                return None
        if len(self._cache) > 4000:  # bounded memory
            self._cache = dict(list(self._cache.items())[-2000:])
        return [self._cache[t] for t in texts if t in self._cache] or None


class AdaptiveRAG:
    """Adaptive Retrieval-Augmented Generation memory.

    Uses TF-IDF vectorization with cosine similarity, fully self-contained
    (no external dependencies), with optional ChromaDB upgrade path.
    """

    def __init__(self, persist_path: str | Path = "zahra_data/ai_agent_rag.json") -> None:
        self.persist_path = Path(persist_path)
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)

        # Knowledge store: list of {id, content, category, metadata, timestamp}
        self._entries: list[dict[str, Any]] = []
        self._id_counter = 0
        self._embedder = _OllamaEmbedder()
        self._embed_cache: dict[str, list[float]] = {}  # entry_id -> vector (session only)

        self._load()
        self._load_embeddings()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if self.persist_path.exists():
            try:
                data = json.loads(self.persist_path.read_text(encoding="utf-8"))
                self._entries = data.get("entries", [])
                self._id_counter = data.get("id_counter", 0)
                logger.info("RAG memory loaded: %d entries from %s", len(self._entries), self.persist_path)
            except Exception:
                logger.exception("Failed to load RAG memory")

    def _save(self) -> None:
        try:
            self.persist_path.write_text(
                json.dumps(
                    {"entries": self._entries, "id_counter": self._id_counter},
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
        except Exception:
            logger.exception("Failed to save RAG memory")

    # -- storage -------------------------------------------------------------

    def store(
        self,
        content: str,
        category: str = "general",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a knowledge chunk and return its ID."""
        self._id_counter += 1
        entry_id = f"entry_{self._id_counter}"
        self._entries.append(
            {
                "id": entry_id,
                "content": content,
                "category": category,
                "metadata": metadata or {},
                "timestamp": time.time(),
                "hits": 0,
            }
        )

        # Keep only the last 5000 entries
        if len(self._entries) > 5000:
            self._entries = self._entries[-5000:]

        self._save()

        # Also try to store in ChromaDB (with explicit Ollama embeddings)
        self._store_chromadb(entry_id, content, category, metadata)

        return entry_id

    def _load_embeddings(self) -> None:
        """Re-hydrate session vector cache from the JSON sidecar if present."""
        sidecar = self.persist_path.with_suffix(".emb.json")
        if not sidecar.exists():
            return
        try:
            data = json.loads(sidecar.read_text(encoding="utf-8"))
            self._embed_cache = {k: v for k, v in data.items() if isinstance(v, list)}
            logger.info("RAG embeddings re-hydrated: %d vectors", len(self._embed_cache))
        except Exception:
            pass

    def _save_embeddings(self) -> None:
        try:
            self.persist_path.with_suffix(".emb.json").write_text(
                json.dumps(self._embed_cache), encoding="utf-8"
            )
        except Exception:
            pass

    def _store_chromadb(
        self, entry_id: str, content: str, category: str, metadata: dict[str, Any] | None
    ) -> None:
        """ChromaDB store with explicit embeddings. Silently skipped if
        Ollama embeddings are unavailable or Chroma is not installed."""
        try:
            embedding = self._embedder.embed([content])
            if not embedding:
                return
            import chromadb

            client = chromadb.PersistentClient(path="zahra_data/ai_agent_chroma")
            collection = client.get_or_create_collection("ai_agent_knowledge")
            collection.upsert(
                ids=[entry_id],
                documents=[content],
                embeddings=[embedding[0]],
                metadatas=[{"category": category, **(metadata or {})}],
            )
            self._embed_cache[entry_id] = embedding[0]
            self._save_embeddings()
        except Exception:
            pass  # ChromaDB / embeddings are optional

    # -- retrieval -----------------------------------------------------------

    def search(self, query: str, top_k: int = 5, category: str | None = None) -> list[dict[str, Any]]:
        """Search for knowledge relevant to a query.

        Hybrid retrieval:
        1. ChromaDB semantic search (Ollama embeddings) when available
        2. TF-IDF cosine fallback (built-in, dependency-free)
        """
        results = self._search_chromadb(query, top_k, category)
        if results:
            return results
        return self._search_tfidf(query, top_k, category)

    def _search_chromadb(
        self, query: str, top_k: int, category: str | None
    ) -> list[dict[str, Any]]:
        try:
            qvec = self._embedder.embed([query])
            if not qvec or not self._embed_cache:
                return []
            import chromadb

            client = chromadb.PersistentClient(path="zahra_data/ai_agent_chroma")
            collection = client.get_or_create_collection("ai_agent_knowledge")
            where = {"category": category} if category else None
            result = collection.query(
                query_embeddings=[qvec[0]],
                n_results=top_k,
                where=where,
            )
            items = []
            for i, doc in enumerate(result.get("documents", [[]])[0]):
                meta = result.get("metadatas", [[]])[0][i] or {}
                dist = result.get("distances", [[0]])[0][i] if result.get("distances") else 0
                items.append(
                    {
                        "content": doc,
                        "category": meta.get("category", ""),
                        "metadata": meta,
                        "score": round(float(1.0 - dist), 4),
                    }
                )
            return items
        except Exception:
            return []

    def _tokenize(self, text: str) -> list[str]:
        """Tokenizer that preserves compound IDs (CVE-2021-44228, OWASP Top 10)
        as whole tokens while still yielding their atomic parts."""
        tokens: list[str] = []
        for tok in re.findall(r"[a-z0-9]+(?:[-.][a-z0-9]+)*", text.lower()):
            if _COMPOUND_RE.match(tok) and len(tok) >= 9:
                tokens.append(tok)  # whole ID, e.g. cve-2021-44228
            tokens.extend(re.findall(r"[a-z0-9]+", tok))
        return tokens

    def _cosine(self, a: list[float], b: list[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb) if na and nb else 0.0

    def _search_tfidf(
        self, query: str, top_k: int, category: str | None
    ) -> list[dict[str, Any]]:
        """TF-IDF based search with cosine similarity."""
        if not self._entries:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        # Filter by category if specified
        items = self._entries
        if category:
            items = [e for e in items if e.get("category") == category]

        if not items:
            return []

        # Build document frequency
        doc_freq: Counter = Counter()
        for entry in items:
            token_set = set(self._tokenize(entry.get("content", "")))
            for t in token_set:
                doc_freq[t] += 1

        n_docs = len(items)

        # Query embedding (once) for semantic blending when session vectors exist
        qvec = self._embedder.embed([query]) if self._embed_cache else None
        qvec = qvec[0] if qvec else None

        # Score each entry with TF-IDF cosine similarity
        scored: list[tuple[float, dict[str, Any]]] = []
        for entry in items:
            content = entry.get("content", "")
            tokens = self._tokenize(content)
            if not tokens:
                continue

            # TF vector
            tf = Counter(tokens)
            query_tf = Counter(query_tokens)

            # Compute cosine similarity
            dot = 0.0
            norm_a = 0.0
            norm_b = 0.0
            for t, q_count in query_tf.items():
                if t in tf:
                    idf = math.log(1 + n_docs / (1 + doc_freq[t]))
                    w_q = (1 + math.log(q_count)) * idf
                    w_d = (1 + math.log(tf[t])) * idf
                    dot += w_q * w_d
                norm_b += (1 + math.log(q_count)) ** 2
            for t, count in tf.items():
                idf = math.log(1 + n_docs / (1 + doc_freq[t]))
                norm_a += ((1 + math.log(count)) * idf) ** 2

            if norm_a == 0 or norm_b == 0:
                continue

            similarity = dot / (math.sqrt(norm_a) * math.sqrt(norm_b))

            score = similarity

            # Semantic blend: embedding cosine when session vectors exist
            ecos = 0.0
            if qvec:
                entry_vec = self._embed_cache.get(entry.get("id", ""))
                if entry_vec:
                    ecos = self._cosine(qvec, entry_vec)
            if ecos:
                score = 0.65 * ecos + 0.35 * similarity

            # Recency boost: newer entries score slightly higher
            age_hours = (time.time() - entry.get("timestamp", time.time())) / 3600.0
            recency_boost = 1.0 / (1.0 + age_hours / 24.0) * 0.08

            # Hit boost: frequently accessed entries score higher
            hit_boost = min(entry.get("hits", 0), 10) * 0.01

            final_score = score + recency_boost + hit_boost

            if score > 0.01:
                scored.append((final_score, entry))

        # Sort by score
        scored.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, entry in scored[:top_k]:
            # Increment hit count
            entry["hits"] = entry.get("hits", 0) + 1
            results.append(
                {
                    "content": entry.get("content", ""),
                    "category": entry.get("category", ""),
                    "metadata": entry.get("metadata", {}),
                    "score": round(score, 4),
                }
            )

        if results:
            self._save()

        return results

    # -- utilities -----------------------------------------------------------

    def recall(self, category: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent knowledge entries."""
        items = self._entries
        if category:
            items = [e for e in items if e.get("category") == category]
        return sorted(items, key=lambda e: e.get("timestamp", 0), reverse=True)[:limit]

    def stats(self) -> dict[str, Any]:
        """Get RAG statistics."""
        categories: Counter = Counter(e.get("category", "general") for e in self._entries)
        return {
            "total_entries": len(self._entries),
            "categories": dict(categories),
            "persist_path": str(self.persist_path),
        }

    def clear(self) -> None:
        """Clear all knowledge."""
        self._entries = []
        self._id_counter = 0
        self._save()