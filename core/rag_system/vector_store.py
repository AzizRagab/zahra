"""Vector store — persistent embedding database for the Adaptive RAG system.

Uses ChromaDB (local, persistent) to store and retrieve semantic memories:
findings, successful commands, failed commands, and evasion techniques.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("zahra.rag.vector_store")


class RAGVectorStore:
    """Persistent vector store backed by ChromaDB.

    Collections:
    * ``findings`` — discovered vulnerabilities / open ports / services
    * ``commands`` — successful & failed commands with outcomes
    * ``evasions`` — evasion techniques that worked against specific WAFs
    """

    def __init__(self, persist_dir: str | Path = "zahra_data/rag") -> None:
        self._persist_dir = Path(persist_dir)
        self._persist_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._client: Any = None
        self._collections: dict[str, Any] = {}
        self._setup()

    def _setup(self) -> None:
        """Initialize the ChromaDB client and collections."""
        try:
            import chromadb  # type: ignore

            self._client = chromadb.PersistentClient(path=str(self._persist_dir))
            for name in ("findings", "commands", "evasions"):
                self._collections[name] = self._client.get_or_create_collection(
                    name=name,
                    metadata={"hnsw:space": "cosine"},
                )
            logger.info(
                "RAG vector store ready at %s (collections: %s)",
                self._persist_dir,
                ", ".join(self._collections),
            )
        except Exception:
            logger.exception("failed to initialize ChromaDB; RAG disabled")
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    # -- generic add -------------------------------------------------------

    def _add(
        self,
        collection: str,
        text: str,
        *,
        category: str = "",
        target: str = "",
        agent: str = "",
        outcome: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Add a document to a collection and return its ID."""
        if not self.available:
            return None
        doc_id = str(uuid.uuid4())
        meta: dict[str, Any] = {
            "category": category,
            "target": target,
            "agent": agent,
            "outcome": outcome,
            "timestamp": time.time(),
        }
        if metadata:
            meta.update(metadata)
        try:
            with self._lock:
                self._collections[collection].add(
                    ids=[doc_id],
                    documents=[text],
                    metadatas=[meta],
                )
            return doc_id
        except Exception:
            logger.exception("failed to add to RAG collection %s", collection)
            return None

    # -- semantic search ---------------------------------------------------

    def _query(
        self,
        collection: str,
        query_text: str,
        *,
        n_results: int = 5,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Semantic search over a collection."""
        if not self.available:
            return []
        try:
            with self._lock:
                kwargs: dict[str, Any] = {
                    "query_texts": [query_text],
                    "n_results": n_results,
                }
                if where:
                    kwargs["where"] = where
                result = self._collections[collection].query(**kwargs)
            docs = result.get("documents", [[]])[0]
            metas = result.get("metadatas", [[]])[0]
            dists = result.get("distances", [[]])[0]
            ids = result.get("ids", [[]])[0]
            out: list[dict[str, Any]] = []
            for i, doc in enumerate(docs):
                out.append({
                    "id": ids[i] if i < len(ids) else "",
                    "text": doc,
                    "metadata": metas[i] if i < len(metas) else {},
                    "distance": dists[i] if i < len(dists) else 0.0,
                })
            return out
        except Exception:
            logger.exception("RAG query failed on %s", collection)
            return []

    # -- domain-specific helpers -------------------------------------------

    def add_finding(
        self,
        text: str,
        *,
        target: str = "",
        agent: str = "",
        severity: str = "info",
        finding_type: str = "info",
    ) -> str | None:
        return self._add(
            "findings",
            text,
            category="finding",
            target=target,
            agent=agent,
            outcome="discovered",
            metadata={"severity": severity, "finding_type": finding_type},
        )

    def add_command(
        self,
        command: str,
        *,
        target: str = "",
        agent: str = "",
        success: bool = True,
        output: str = "",
    ) -> str | None:
        return self._add(
            "commands",
            f"Command: {command}\nOutput: {output[:500]}",
            category="command",
            target=target,
            agent=agent,
            outcome="success" if success else "failed",
            metadata={"success": success},
        )

    def add_evasion(
        self,
        technique: str,
        *,
        target: str = "",
        agent: str = "",
        waf: str = "",
        success: bool = True,
    ) -> str | None:
        return self._add(
            "evasions",
            f"Evasion technique: {technique}\nWAF: {waf}",
            category="evasion",
            target=target,
            agent=agent,
            outcome="success" if success else "failed",
            metadata={"waf": waf, "success": success},
        )

    # -- search helpers ----------------------------------------------------

    def search_findings(self, query: str, n: int = 5) -> list[dict[str, Any]]:
        return self._query("findings", query, n_results=n)

    def search_commands(self, query: str, n: int = 5) -> list[dict[str, Any]]:
        return self._query("commands", query, n_results=n)

    def search_evasions(self, query: str, n: int = 5) -> list[dict[str, Any]]:
        return self._query("evasions", query, n_results=n)

    def search_all(self, query: str, n: int = 5) -> list[dict[str, Any]]:
        """Search across all collections and merge results."""
        results: list[dict[str, Any]] = []
        for coll in ("findings", "commands", "evasions"):
            results.extend(self._query(coll, query, n_results=n))
        # Sort by distance (lower = more similar)
        results.sort(key=lambda r: r.get("distance", 1.0))
        return results[:n]

    # -- stats -------------------------------------------------------------

    def count(self, collection: str | None = None) -> int:
        if not self.available:
            return 0
        try:
            with self._lock:
                if collection:
                    return self._collections[collection].count()
                return sum(c.count() for c in self._collections.values())
        except Exception:
            return 0

    def summary(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "findings": self.count("findings"),
            "commands": self.count("commands"),
            "evasions": self.count("evasions"),
            "total": self.count(),
        }