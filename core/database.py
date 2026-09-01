"""Database — SQLite persistent storage for ZAHRA v3.0.

Stores campaigns, findings, agent states, and RAG history in a
persistent SQLite database so data survives restarts.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("zahra.core.database")


class Database:
    """SQLite database for persistent ZAHRA data."""

    def __init__(self, db_path: str | Path = "zahra_data/zahra.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS campaigns (
                        id TEXT PRIMARY KEY,
                        command TEXT NOT NULL,
                        target TEXT NOT NULL,
                        intent TEXT DEFAULT 'unknown',
                        status TEXT DEFAULT 'pending',
                        created_at REAL DEFAULT 0,
                        started_at REAL DEFAULT 0,
                        finished_at REAL DEFAULT 0,
                        error TEXT DEFAULT '',
                        findings_count INTEGER DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        campaign_id TEXT,
                        agent_name TEXT NOT NULL,
                        finding_type TEXT DEFAULT 'info',
                        target TEXT DEFAULT '',
                        severity TEXT DEFAULT 'info',
                        description TEXT DEFAULT '',
                        evidence TEXT DEFAULT '',
                        confidence REAL DEFAULT 0.5,
                        timestamp REAL DEFAULT 0,
                        metadata TEXT DEFAULT '{}',
                        FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                    );

                    CREATE TABLE IF NOT EXISTS agent_states (
                        id TEXT PRIMARY KEY,
                        campaign_id TEXT,
                        agent_name TEXT NOT NULL,
                        status TEXT DEFAULT 'idle',
                        last_command TEXT DEFAULT '',
                        findings_count INTEGER DEFAULT 0,
                        started_at REAL DEFAULT 0,
                        finished_at REAL DEFAULT 0,
                        FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                    );

                    CREATE TABLE IF NOT EXISTS rag_history (
                        id TEXT PRIMARY KEY,
                        category TEXT NOT NULL,
                        content TEXT NOT NULL,
                        target TEXT DEFAULT '',
                        agent TEXT DEFAULT '',
                        success INTEGER DEFAULT 0,
                        metadata TEXT DEFAULT '{}',
                        created_at REAL DEFAULT 0
                    );

                    CREATE INDEX IF NOT EXISTS idx_findings_campaign ON findings(campaign_id);
                    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                    CREATE INDEX IF NOT EXISTS idx_agent_states_campaign ON agent_states(campaign_id);
                """)
                conn.commit()
                logger.info("Database initialized at %s", self._db_path)
            finally:
                conn.close()

    # -- Campaigns ---------------------------------------------------------

    def save_campaign(self, campaign: dict[str, Any]) -> None:
        """Insert or update a campaign."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO campaigns
                    (id, command, target, intent, status, created_at, started_at, finished_at, error, findings_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign.get("id", str(uuid.uuid4())),
                    campaign.get("command", ""),
                    campaign.get("target", ""),
                    campaign.get("intent", "unknown"),
                    campaign.get("status", "pending"),
                    campaign.get("created_at", time.time()),
                    campaign.get("started_at", 0),
                    campaign.get("finished_at", 0),
                    campaign.get("error", ""),
                    campaign.get("findings_count", 0),
                ))
                conn.commit()
            finally:
                conn.close()

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        """Get a campaign by ID."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_campaigns(self, limit: int = 100) -> list[dict[str, Any]]:
        """List all campaigns."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # -- Findings ----------------------------------------------------------

    def save_finding(self, finding: dict[str, Any]) -> None:
        """Insert a finding."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO findings
                    (id, campaign_id, agent_name, finding_type, target, severity,
                     description, evidence, confidence, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding.get("id", str(uuid.uuid4())),
                    finding.get("campaign_id", ""),
                    finding.get("agent_name", ""),
                    finding.get("finding_type", "info"),
                    finding.get("target", ""),
                    finding.get("severity", "info"),
                    finding.get("description", ""),
                    finding.get("evidence", ""),
                    finding.get("confidence", 0.5),
                    finding.get("timestamp", time.time()),
                    json.dumps(finding.get("metadata", {})),
                ))
                conn.commit()
            finally:
                conn.close()

    def get_findings(self, campaign_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Get findings, optionally filtered by campaign."""
        with self._lock:
            conn = self._get_conn()
            try:
                if campaign_id:
                    rows = conn.execute(
                        "SELECT * FROM findings WHERE campaign_id = ? ORDER BY timestamp DESC LIMIT ?",
                        (campaign_id, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,)
                    ).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    d["metadata"] = json.loads(d.get("metadata", "{}"))
                    results.append(d)
                return results
            finally:
                conn.close()

    # -- Agent States ------------------------------------------------------

    def save_agent_state(self, state: dict[str, Any]) -> None:
        """Insert or update an agent state."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO agent_states
                    (id, campaign_id, agent_name, status, last_command,
                     findings_count, started_at, finished_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    state.get("id", str(uuid.uuid4())),
                    state.get("campaign_id", ""),
                    state.get("agent_name", ""),
                    state.get("status", "idle"),
                    state.get("last_command", ""),
                    state.get("findings_count", 0),
                    state.get("started_at", 0),
                    state.get("finished_at", 0),
                ))
                conn.commit()
            finally:
                conn.close()

    def get_agent_states(self, campaign_id: str | None = None) -> list[dict[str, Any]]:
        """Get agent states."""
        with self._lock:
            conn = self._get_conn()
            try:
                if campaign_id:
                    rows = conn.execute(
                        "SELECT * FROM agent_states WHERE campaign_id = ?",
                        (campaign_id,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM agent_states ORDER BY started_at DESC LIMIT 50"
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # -- RAG History -------------------------------------------------------

    def save_rag_entry(self, entry: dict[str, Any]) -> None:
        """Insert a RAG history entry."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO rag_history
                    (id, category, content, target, agent, success, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    entry.get("category", ""),
                    entry.get("content", ""),
                    entry.get("target", ""),
                    entry.get("agent", ""),
                    1 if entry.get("success", False) else 0,
                    json.dumps(entry.get("metadata", {})),
                    time.time(),
                ))
                conn.commit()
            finally:
                conn.close()

    def get_rag_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get RAG history entries."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM rag_history ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    d["success"] = bool(d.get("success", 0))
                    d["metadata"] = json.loads(d.get("metadata", "{}"))
                    results.append(d)
                return results
            finally:
                conn.close()

    # -- Table Explorer ----------------------------------------------------

    def list_tables(self) -> list[str]:
        """List all user tables in the database."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
                return [r["name"] for r in rows]
            finally:
                conn.close()

    def get_table_data(self, table: str, limit: int = 100) -> dict[str, Any]:
        """Get columns and rows from a table (safe, read-only)."""
        # Whitelist allowed tables to prevent SQL injection.
        allowed = {"campaigns", "findings", "agent_states", "rag_history"}
        if table not in allowed:
            raise ValueError(f"Table '{table}' is not accessible")
        with self._lock:
            conn = self._get_conn()
            try:
                cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
                columns = [c["name"] for c in cols]
                rows = conn.execute(
                    f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT ?", (limit,)
                ).fetchall()
                return {
                    "table": table,
                    "columns": columns,
                    "rows": [dict(r) for r in rows],
                }
            finally:
                conn.close()

    # -- Stats -------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Get database statistics."""
        with self._lock:
            conn = self._get_conn()
            try:
                campaigns = conn.execute("SELECT COUNT(*) as c FROM campaigns").fetchone()["c"]
                findings = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
                agents = conn.execute("SELECT COUNT(*) as c FROM agent_states").fetchone()["c"]
                rag = conn.execute("SELECT COUNT(*) as c FROM rag_history").fetchone()["c"]
                return {
                    "campaigns": campaigns,
                    "findings": findings,
                    "agent_states": agents,
                    "rag_entries": rag,
                }
            finally:
                conn.close()
