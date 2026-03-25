"""
ChromaDB vector store wrapper.

Uses sentence-transformers locally — no API key, no cost.
Collection: siem_logs — each document is a LogChunk summary text.
"""
from __future__ import annotations

import logging
from typing import Any

import chromadb
from chromadb.utils import embedding_functions

from vegapunk.config import settings
from vegapunk.models import LogChunk, NormEvent

logger = logging.getLogger(__name__)


class VectorStore:
    """Persistent ChromaDB collection for semantic log search."""

    def __init__(self) -> None:
        self._client = chromadb.PersistentClient(
            path=str(settings.chroma_persist_dir)
        )
        self._ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=settings.embedding_model
        )
        self._collection = self._client.get_or_create_collection(
            name=settings.chroma_collection,
            embedding_function=self._ef,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("VectorStore ready — %d documents", self._collection.count())

    # ── Write ───────────────────────────────────────────────────────────────

    def add_chunk(self, chunk: LogChunk) -> None:
        """Embed and store a LogChunk as a single document."""
        self._collection.upsert(
            ids=[chunk.id],
            documents=[chunk.summary_text],
            metadatas=[{
                "source_type": chunk.source_type,
                "window_start": chunk.window_start.isoformat(),
                "window_end": chunk.window_end.isoformat(),
                "event_count": len(chunk.events),
            }],
        )

    def add_event(self, event: NormEvent) -> None:
        """Embed and store a single NormEvent."""
        self._collection.upsert(
            ids=[event.id],
            documents=[event.to_text()],
            metadatas=[{
                "source_type": event.source_type,
                "timestamp": event.timestamp.isoformat(),
                "severity": event.severity.value,
                "host": event.host or "",
                "user": event.user or "",
                "event_category": event.event_category or "",
            }],
        )

    # ── Read ────────────────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        n_results: int | None = None,
        where: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Semantic similarity search. Returns list of result dicts."""
        n = n_results or settings.max_rag_results
        kwargs: dict[str, Any] = {"query_texts": [query], "n_results": min(n, self._collection.count() or 1)}
        if where:
            kwargs["where"] = where

        results = self._collection.query(**kwargs)
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        return [
            {"document": doc, "metadata": meta, "distance": dist}
            for doc, meta, dist in zip(docs, metas, distances)
        ]

    def count(self) -> int:
        return self._collection.count()
