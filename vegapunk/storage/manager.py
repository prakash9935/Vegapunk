"""
Unified StorageManager — single interface for all storage operations.

Agents and interfaces interact only with this class, never directly
with ChromaDB or SQLite. This keeps the storage backends swappable.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from vegapunk.models import AnalysisResult, LogChunk, NormEvent, TriageResult
from vegapunk.storage.metadata_store import MetadataStore
from vegapunk.storage.vector_store import VectorStore

logger = logging.getLogger(__name__)


class StorageManager:
    """Facade over VectorStore (ChromaDB) and MetadataStore (SQLite)."""

    def __init__(self) -> None:
        # Eager init — both backends created once in the calling thread.
        # @cached_property is not thread-safe; run_in_executor threads would
        # race and each create their own ChromaDB client, crashing the process.
        self.vector = VectorStore()
        self.metadata = MetadataStore()

    # ── Write ───────────────────────────────────────────────────────────────

    async def store_chunk(self, chunk: LogChunk) -> None:
        """Store a LogChunk in both backends (async-safe)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._store_chunk_sync, chunk)

    def _store_chunk_sync(self, chunk: LogChunk) -> None:
        self.metadata.insert_chunk(chunk)
        self.vector.add_chunk(chunk)
        for event in chunk.events:
            self.vector.add_event(event)
        logger.debug("Stored chunk %s (%d events)", chunk.id, len(chunk.events))

    async def store_triage(self, result: TriageResult) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.metadata.insert_triage, result)

    async def store_analysis(self, result: AnalysisResult) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.metadata.insert_analysis, result)

    # ── Read ────────────────────────────────────────────────────────────────

    def semantic_search(self, query: str, n: int = 8, **filters) -> list[dict[str, Any]]:
        """Semantic vector search with optional metadata filters."""
        where = {k: v for k, v in filters.items() if v} or None
        return self.vector.search(query, n_results=n, where=where)

    def sql_query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        """Execute a raw SQL query against the metadata store."""
        return self.metadata.query(sql, params)

    def recent_events(self, limit: int = 50, severity: str | None = None) -> list[dict]:
        return self.metadata.recent_events(limit=limit, severity=severity)

    def stats(self) -> dict[str, Any]:
        return {
            "vector_documents": self.vector.count(),
            "events_by_severity": self.metadata.event_count_by_severity(),
        }
