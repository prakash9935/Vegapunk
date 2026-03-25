"""
SQLite metadata store.

Stores structured event metadata for fast SQL queries.
WAL mode enabled for concurrent reads (Streamlit + CLI at the same time).

Schema:
  events  — one row per NormEvent
  chunks  — one row per LogChunk
  alerts  — triage/analysis results
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from vegapunk.config import settings
from vegapunk.models import AnalysisResult, LogChunk, NormEvent, TriageResult

logger = logging.getLogger(__name__)

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS chunks (
    id           TEXT PRIMARY KEY,
    source_type  TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,
    event_count  INTEGER NOT NULL,
    created_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id             TEXT PRIMARY KEY,
    chunk_id       TEXT REFERENCES chunks(id),
    source_type    TEXT NOT NULL,
    timestamp      TEXT NOT NULL,
    message        TEXT,
    host           TEXT,
    source_ip      TEXT,
    dest_ip        TEXT,
    username       TEXT,
    process        TEXT,
    event_category TEXT,
    event_action   TEXT,
    severity       TEXT NOT NULL,
    tags           TEXT,       -- JSON array
    raw            TEXT        -- JSON blob
);

CREATE TABLE IF NOT EXISTS triage_results (
    id              TEXT PRIMARY KEY,
    event_id        TEXT REFERENCES events(id),
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    summary         TEXT,
    needs_deep      INTEGER NOT NULL,
    mitre_tactics   TEXT,      -- JSON array
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id                 TEXT PRIMARY KEY,
    event_id           TEXT REFERENCES events(id),
    severity           TEXT NOT NULL,
    summary            TEXT,
    root_cause         TEXT,
    mitre_techniques   TEXT,   -- JSON array
    recommended_actions TEXT,  -- JSON array
    related_event_ids  TEXT,   -- JSON array
    created_at         TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp    ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity     ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source_ip    ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_host         ON events(host);
CREATE INDEX IF NOT EXISTS idx_triage_event        ON triage_results(event_id);
"""


class MetadataStore:
    """SQLite-backed store for structured event metadata and alert results."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or settings.sqlite_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        logger.info("MetadataStore ready at %s", self._path)

    # ── Connection ──────────────────────────────────────────────────────────

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        con = sqlite3.connect(self._path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _init_schema(self) -> None:
        with self._conn() as con:
            con.executescript(_DDL)

    # ── Write ───────────────────────────────────────────────────────────────

    def insert_chunk(self, chunk: LogChunk) -> None:
        with self._conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO chunks VALUES (?,?,?,?,?,datetime('now'))",
                (chunk.id, chunk.source_type,
                 chunk.window_start.isoformat(), chunk.window_end.isoformat(),
                 len(chunk.events)),
            )
            for event in chunk.events:
                self._insert_event(con, event, chunk.id)

    def _insert_event(self, con: sqlite3.Connection, event: NormEvent, chunk_id: str) -> None:
        con.execute(
            """INSERT OR REPLACE INTO events
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.id, chunk_id, event.source_type,
                event.timestamp.isoformat(), event.message,
                event.host, event.source_ip, event.dest_ip,
                event.user, event.process, event.event_category,
                event.event_action, event.severity.value,
                json.dumps(event.tags), json.dumps(event.raw),
            ),
        )

    def insert_triage(self, result: TriageResult) -> None:
        import uuid
        with self._conn() as con:
            con.execute(
                """INSERT OR REPLACE INTO triage_results VALUES (?,?,?,?,?,?,?,datetime('now'))""",
                (str(uuid.uuid4()), result.event_id, result.severity.value,
                 result.confidence, result.summary, int(result.needs_deep_analysis),
                 json.dumps(result.mitre_tactics)),
            )

    def insert_analysis(self, result: AnalysisResult) -> None:
        import uuid
        with self._conn() as con:
            con.execute(
                """INSERT OR REPLACE INTO analysis_results VALUES (?,?,?,?,?,?,?,?,datetime('now'))""",
                (str(uuid.uuid4()), result.event_id, result.severity.value,
                 result.summary, result.root_cause,
                 json.dumps(result.mitre_techniques),
                 json.dumps(result.recommended_actions),
                 json.dumps(result.related_event_ids)),
            )

    # ── Read ────────────────────────────────────────────────────────────────

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        """Execute a read-only SQL query and return results as dicts."""
        with self._conn() as con:
            rows = con.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def recent_events(self, limit: int = 50, severity: str | None = None) -> list[dict]:
        where = "WHERE severity = ?" if severity else ""
        params = (severity,) if severity else ()
        return self.query(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?",
            (*params, limit),
        )

    def event_count_by_severity(self) -> dict[str, int]:
        rows = self.query("SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity")
        return {r["severity"]: r["cnt"] for r in rows}

    def search_events(self, **filters: Any) -> list[dict]:
        clauses, params = [], []
        for col, val in filters.items():
            if val:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.query(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT 100",
            tuple(params),
        )
