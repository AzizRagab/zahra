"""Agent memory — persists findings and learned patterns across campaigns.

Inspired by Pentest-Swarm-AI's ``internal/memory/store.go`` and strix's
session snapshots. The memory store is the long-term knowledge base that
agents consult before launching new attacks so they don't repeat dead-ends
or re-discover already-known facts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, AsyncIterator

from core.rag_system.retriever import RAGRetriever
from core.rag_system.vector_store import RAGVectorStore

logger = logging.getLogger("zahra.core.memory")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class MemoryEntry:
    """A single learned pattern or recorded finding.

    Attributes:
        id: Unique identifier.
        category: Logical bucket — ``tech_stack``, ``attack_chain``,
            ``false_positive``, ``credential``, ``timing``, etc.
        pattern: Human-readable description of the pattern.
        target: The target host / scope the entry applies to.
        confidence: 0.0 – 1.0 confidence score.
        usage_count: How many times this entry has been recalled.
        last_used: Unix timestamp of last recall.
        created_at: Unix timestamp of creation.
        metadata: Free-form extra context.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    pattern: str = ""
    target: str = ""
    confidence: float = 0.5
    usage_count: int = 0
    last_used: float = 0.0
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict[str, Any])

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = time.time()
        if not self.last_used:
            self.last_used = self.created_at

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryEntry":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Finding:
    """A concrete finding discovered during a campaign.

    Findings flow through the blackboard / swarm and may be persisted to
    memory once confirmed.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    finding_type: str = "info"  # info, vuln, credential, recon, error
    target: str = ""
    severity: str = "info"  # info, low, medium, high, critical
    description: str = ""
    evidence: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Memory store
# ---------------------------------------------------------------------------


class MemoryStore:
    """Thread-safe persistent memory for the zahra swarm.

    The store keeps an in-memory index for fast recall and optionally
    mirrors state to a JSON file on disk so knowledge survives restarts.
    """

    def __init__(
        self,
        persist_path: str | Path | None = None,
        rag_persist_dir: str | Path = "zahra_data/rag",
    ) -> None:
        self._lock = threading.RLock()
        self._entries: list[MemoryEntry] = []
        self._findings: list[Finding] = []
        self._persist_path = Path(persist_path) if persist_path else None
        # Adaptive RAG system — the growing brain.
        self.rag = RAGRetriever(RAGVectorStore(rag_persist_dir))
        self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        if self._persist_path is None or not self._persist_path.exists():
            return
        try:
            data = json.loads(self._persist_path.read_text(encoding="utf-8"))
            self._entries = [MemoryEntry.from_dict(e) for e in data.get("entries", [])]
            self._findings = [Finding.from_dict(f) for f in data.get("findings", [])]
            logger.info(
                "loaded %d entries and %d findings from %s",
                len(self._entries),
                len(self._findings),
                self._persist_path,
            )
        except Exception:
            logger.exception("failed to load memory from %s", self._persist_path)

    def _save(self) -> None:
        if self._persist_path is None:
            return
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "entries": [e.to_dict() for e in self._entries],
                "findings": [f.to_dict() for f in self._findings],
            }
            self._persist_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except Exception:
            logger.exception("failed to persist memory to %s", self._persist_path)

    # -- entries -----------------------------------------------------------

    def save(self, entry: MemoryEntry) -> MemoryEntry:
        """Persist a new memory entry."""
        with self._lock:
            if not entry.created_at:
                entry.created_at = time.time()
            entry.last_used = time.time()
            entry.usage_count = max(entry.usage_count, 1)
            self._entries.append(entry)
            self._save()
        logger.debug("saved memory entry: %s", entry.id)
        return entry

    def recall_relevant(self, keywords: list[str], limit: int = 50) -> list[MemoryEntry]:
        """Return entries whose pattern or target matches any keyword (case-insensitive)."""
        if not keywords:
            return []
        lowered = [k.lower() for k in keywords]
        with self._lock:
            relevant: list[MemoryEntry] = []
            for entry in self._entries:
                haystack = f"{entry.pattern} {entry.target} {entry.category}".lower()
                if any(kw in haystack for kw in lowered):
                    entry.usage_count += 1
                    entry.last_used = time.time()
                    relevant.append(entry)
                if len(relevant) >= limit:
                    break
            self._save()
        return relevant

    def recall_by_category(self, category: str) -> list[MemoryEntry]:
        with self._lock:
            return [e for e in self._entries if e.category == category]

    def recall_by_target(self, target: str) -> list[MemoryEntry]:
        with self._lock:
            return [e for e in self._entries if target in e.target or e.target in target]

    def all_entries(self) -> list[MemoryEntry]:
        with self._lock:
            return list(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._findings.clear()
            self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    # -- findings ----------------------------------------------------------

    def record_finding(self, finding: Finding) -> Finding:
        with self._lock:
            self._findings.append(finding)
            self._save()
        # Also store in the RAG vector store for semantic recall.
        self.rag.record_finding(
            f"{finding.finding_type}: {finding.description}",
            target=finding.target,
            agent=finding.agent_name,
            severity=finding.severity,
            finding_type=finding.finding_type,
        )
        logger.debug("recorded finding: %s (%s)", finding.id, finding.finding_type)
        return finding

    def findings_for(self, target: str) -> list[Finding]:
        with self._lock:
            return [f for f in self._findings if f.target == target]

    def all_findings(self) -> list[Finding]:
        with self._lock:
            return list(self._findings)

    # -- summary -----------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        with self._lock:
            categories: dict[str, int] = {}
            for e in self._entries:
                categories[e.category] = categories.get(e.category, 0) + 1
            severities: dict[str, int] = {}
            for f in self._findings:
                severities[f.severity] = severities.get(f.severity, 0) + 1
            return {
                "entries": len(self._entries),
                "findings": len(self._findings),
                "categories": categories,
                "severities": severities,
                "rag": self.rag.summary(),
            }


# ---------------------------------------------------------------------------
# Async memory queue (stigmergic blackboard)
# ---------------------------------------------------------------------------


class MemoryQueue:
    """Async stigmergic blackboard for the swarm.

    Agents publish findings to the queue as they discover them. Other
    agents subscribe and react immediately — e.g. the scan agent starts
    scanning port 80 the moment the recon agent publishes it, without
    waiting for recon to finish scanning all ports.

    This is the core of the asynchronous swarm: findings flow through
    the queue (stigmergy) instead of being passed sequentially.
    """

    def __init__(self, maxsize: int = 1000) -> None:
        self._queue: asyncio.Queue[Finding] = asyncio.Queue(maxsize=maxsize)
        self._lock = threading.RLock()
        self._published: list[Finding] = []
        self._closed = False

    # -- publishing --------------------------------------------------------

    def publish(self, finding: Finding) -> None:
        """Publish a finding to the queue (thread-safe, non-blocking).

        If the queue is full, the oldest finding is dropped to avoid
        blocking the producer (the recon agent).
        """
        with self._lock:
            if self._closed:
                return
            self._published.append(finding)
            try:
                self._queue.put_nowait(finding)
            except asyncio.QueueFull:
                # Drop the oldest to keep the pipeline flowing.
                try:
                    self._queue.get_nowait()
                    self._queue.put_nowait(finding)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    def publish_many(self, findings: list[Finding]) -> None:
        for f in findings:
            self.publish(f)

    # -- consumption -------------------------------------------------------

    async def subscribe(self) -> AsyncIterator[Finding]:
        """Async iterator that yields findings as they are published.

        The iterator ends when the queue is closed and drained.
        """
        while True:
            try:
                finding = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                yield finding
            except asyncio.TimeoutError:
                if self._closed and self._queue.empty():
                    return
                continue

    def drain(self) -> list[Finding]:
        """Synchronously drain all currently-queued findings."""
        with self._lock:
            items: list[Finding] = []
            while not self._queue.empty():
                try:
                    items.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            return items

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Close the queue — subscribers will finish after draining."""
        with self._lock:
            self._closed = True

    def is_closed(self) -> bool:
        with self._lock:
            return self._closed

    def size(self) -> int:
        with self._lock:
            return self._queue.qsize()

    def published_count(self) -> int:
        with self._lock:
            return len(self._published)

    def all_published(self) -> list[Finding]:
        with self._lock:
            return list(self._published)

    # -- filtering helpers -------------------------------------------------

    @staticmethod
    def has_open_port(finding: Finding, port: int) -> bool:
        """Check if a finding indicates an open port."""
        meta = finding.metadata or {}
        if meta.get("port") == port:
            return True
        return f"port {port}" in finding.description.lower()

    @staticmethod
    def is_vulnerability(finding: Finding) -> bool:
        """Check if a finding is a vulnerability (for the exploit agent)."""
        return finding.finding_type in ("vuln", "credential", "false_positive")
