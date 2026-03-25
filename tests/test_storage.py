"""Tests for storage layer — MetadataStore, VectorStore, StorageManager."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from vegapunk.models import LogChunk, NormEvent, Severity, TriageResult
from vegapunk.storage.metadata_store import MetadataStore


@pytest.fixture
def meta_store(tmp_path) -> MetadataStore:
    return MetadataStore(db_path=tmp_path / "test.db")


@pytest.fixture
def sample_chunk(sample_norm_event) -> LogChunk:
    return LogChunk(
        window_start=datetime(2024, 1, 15, 10, 0),
        window_end=datetime(2024, 1, 15, 10, 15),
        source_type="splunk",
        events=[sample_norm_event],
    )


class TestMetadataStore:
    def test_insert_and_query_chunk(self, meta_store, sample_chunk):
        meta_store.insert_chunk(sample_chunk)
        rows = meta_store.query("SELECT * FROM chunks")
        assert len(rows) == 1
        assert rows[0]["id"] == sample_chunk.id

    def test_insert_chunk_stores_events(self, meta_store, sample_chunk):
        meta_store.insert_chunk(sample_chunk)
        rows = meta_store.query("SELECT * FROM events")
        assert len(rows) == 1
        assert rows[0]["host"] == "web-server-01"
        assert rows[0]["severity"] == "high"

    def test_recent_events(self, meta_store, sample_chunk):
        meta_store.insert_chunk(sample_chunk)
        events = meta_store.recent_events(limit=10)
        assert len(events) == 1

    def test_severity_filter(self, meta_store, sample_chunk):
        meta_store.insert_chunk(sample_chunk)
        high = meta_store.recent_events(severity="high")
        low = meta_store.recent_events(severity="low")
        assert len(high) == 1
        assert len(low) == 0

    def test_event_count_by_severity(self, meta_store, sample_chunk):
        meta_store.insert_chunk(sample_chunk)
        counts = meta_store.event_count_by_severity()
        assert counts.get("high", 0) == 1

    def test_insert_triage(self, meta_store, sample_norm_event):
        result = TriageResult(
            event_id=sample_norm_event.id,
            severity=Severity.HIGH,
            confidence=0.9,
            summary="Test triage",
            needs_deep_analysis=False,
        )
        meta_store.insert_triage(result)
        rows = meta_store.query("SELECT * FROM triage_results")
        assert len(rows) == 1
        assert rows[0]["confidence"] == 0.9

    def test_sql_injection_safe(self, meta_store):
        # Should not crash or expose data
        rows = meta_store.query("SELECT * FROM events WHERE id = ?", ("'; DROP TABLE events;--",))
        assert rows == []

    def test_upsert_idempotent(self, meta_store, sample_chunk):
        meta_store.insert_chunk(sample_chunk)
        meta_store.insert_chunk(sample_chunk)  # Second insert should upsert
        rows = meta_store.query("SELECT * FROM chunks")
        assert len(rows) == 1
