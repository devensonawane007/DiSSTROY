"""Asynchronous SQLite persistence layer for DiSSTROY."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import aiosqlite


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    criticality REAL NOT NULL,
    network_location TEXT,
    current_access_level TEXT DEFAULT 'NONE',
    is_canary_objective INTEGER DEFAULT 0,
    canary_description TEXT,
    tags TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    raw_payload TEXT,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    tags TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    target_asset_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    supporting_obs TEXT,
    refuting_obs TEXT,
    prerequisite_hypotheses TEXT DEFAULT '[]',
    required_access_level TEXT DEFAULT 'NONE',
    enables_access_level TEXT,
    stage INTEGER DEFAULT 1,
    prior_prob REAL NOT NULL,
    confidence REAL NOT NULL,
    priority_score REAL NOT NULL,
    status TEXT NOT NULL,
    test_plan TEXT,
    assigned_worker_id TEXT,
    generated_by_provider TEXT DEFAULT 'unknown',
    generated_by_model TEXT DEFAULT 'unknown',
    is_fallback INTEGER DEFAULT 0,
    fallback_reason TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(target_asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_asset_id TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    asset_sequence TEXT NOT NULL,
    hypothesis_sequence TEXT NOT NULL,
    path_status TEXT NOT NULL,
    path_confidence REAL NOT NULL,
    path_uncertainty REAL NOT NULL,
    risk_level TEXT NOT NULL,
    is_cycle_detected INTEGER NOT NULL,
    blocked_step_id TEXT,
    canary_target TEXT,
    description TEXT,
    metadata TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(source_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY(target_asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL,
    step_id TEXT,
    worker_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    raw_data TEXT,
    content_hash TEXT NOT NULL,
    supports INTEGER NOT NULL,
    validation_power REAL NOT NULL,
    falsification_power REAL NOT NULL,
    interpretation TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS failures (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    failure_category TEXT NOT NULL,
    error_message TEXT NOT NULL,
    diagnostic_details TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS lessons (
    id TEXT PRIMARY KEY,
    source_failure_id TEXT NOT NULL,
    target_asset_id TEXT,
    affected_category TEXT,
    penalty_factor REAL NOT NULL,
    rule_description TEXT NOT NULL,
    active INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(source_failure_id) REFERENCES failures(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    payload TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_hyp_status ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_hyp_asset ON hypotheses(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_ev_hyp ON evidence(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_fail_hyp ON failures(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_lesson_cat ON lessons(affected_category);
"""


class DatabaseManager:
    """Manages an async SQLite database connection pool and schema lifecycle."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """Open database connection and establish tables."""
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode = WAL;")
        await self._conn.execute("PRAGMA foreign_keys = ON;")
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()

    async def close(self) -> None:
        """Safely close database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if not self._conn:
            raise RuntimeError("Database connection is not initialized. Call initialize() first.")
        return self._conn
