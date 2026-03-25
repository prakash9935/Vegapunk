"""
Async ingestion pipeline.

Accepts log files, parses → normalizes → chunks → stores them.
Uses asyncio.Queue for backpressure so high log volumes don't overwhelm storage.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from vegapunk.config import settings
from vegapunk.ingestion.chunker import chunk_events
from vegapunk.ingestion.normalizer import normalize_event
from vegapunk.ingestion.parsers import PARSER_REGISTRY
from vegapunk.models import LogChunk, NormEvent, RawEvent

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """
    Orchestrates the full parse → normalize → chunk flow.

    Usage:
        pipeline = IngestionPipeline(storage_manager)
        await pipeline.ingest_file(Path("alerts.json"), source_type="wazuh")
    """

    def __init__(self, storage_manager=None) -> None:
        self._storage = storage_manager
        self._queue: asyncio.Queue[LogChunk] = asyncio.Queue(
            maxsize=settings.ingest_queue_size
        )

    # ── Public API ──────────────────────────────────────────────────────────

    async def ingest_file(self, path: Path, source_type: str) -> int:
        """Ingest a SIEM export file. Returns count of chunks stored."""
        parser_cls = PARSER_REGISTRY.get(source_type)
        if not parser_cls:
            raise ValueError(f"Unknown source_type '{source_type}'. "
                             f"Available: {list(PARSER_REGISTRY)}")

        parser = parser_cls()
        raw_events: list[RawEvent] = []

        logger.info("Parsing %s (%s)…", path.name, source_type)
        for raw in parser.parse_file(path):
            raw_events.append(raw)

        norm_events: list[NormEvent] = [normalize_event(r) for r in raw_events]
        chunks = list(chunk_events(norm_events))

        logger.info("Parsed %d events → %d chunks", len(norm_events), len(chunks))

        if self._storage:
            await asyncio.gather(*[self._store_chunk(c) for c in chunks])

        return len(chunks)

    async def ingest_directory(self, directory: Path, source_type: str) -> int:
        """Ingest all JSON/CSV files in a directory."""
        total = 0
        for path in sorted(directory.glob("*.json")) + sorted(directory.glob("*.csv")):
            total += await self.ingest_file(path, source_type)
        return total

    # ── Internal ────────────────────────────────────────────────────────────

    async def _store_chunk(self, chunk: LogChunk) -> None:
        if self._storage:
            await self._storage.store_chunk(chunk)
        else:
            logger.debug("No storage — chunk %s skipped", chunk.id)
