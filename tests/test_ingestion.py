"""Tests for ingestion layer — parsers, normalizer, chunker."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from vegapunk.ingestion.chunker import chunk_events
from vegapunk.ingestion.normalizer import normalize_event
from vegapunk.ingestion.parsers.splunk import SplunkParser
from vegapunk.ingestion.parsers.wazuh import WazuhParser
from vegapunk.models import NormEvent, RawEvent, Severity


class TestSplunkParser:
    def test_parse_json_file(self, splunk_json_file):
        parser = SplunkParser()
        events = list(parser.parse_file(splunk_json_file))
        assert len(events) == 2
        assert all(e.source_type == "splunk" for e in events)

    def test_parse_record_preserves_raw(self, sample_raw_splunk):
        parser = SplunkParser()
        event = parser.parse_record(sample_raw_splunk)
        assert event.raw["host"] == "web-server-01"
        assert event.source_type == "splunk"

    def test_unsupported_format_raises(self, tmp_path):
        parser = SplunkParser()
        bad_file = tmp_path / "data.xml"
        bad_file.write_text("<data/>")
        with pytest.raises(ValueError, match="Unsupported"):
            list(parser.parse_file(bad_file))


class TestWazuhParser:
    def test_parse_json_array(self, wazuh_ndjson_file):
        parser = WazuhParser()
        events = list(parser.parse_file(wazuh_ndjson_file))
        assert len(events) == 1
        assert events[0].source_type == "wazuh"


class TestNormalizer:
    def test_splunk_field_mapping(self, sample_raw_splunk):
        raw = RawEvent(source_type="splunk", raw=sample_raw_splunk)
        norm = normalize_event(raw)
        assert norm.host == "web-server-01"
        assert norm.source_ip == "192.168.1.100"
        assert norm.user == "root"
        assert norm.severity == Severity.HIGH
        assert norm.event_category == "authentication"

    def test_wazuh_field_mapping(self, sample_raw_wazuh):
        raw = RawEvent(source_type="wazuh", raw=sample_raw_wazuh)
        norm = normalize_event(raw)
        assert norm.host == "web-server-01"
        assert norm.source_ip == "192.168.1.100"
        assert norm.severity == Severity.HIGH  # level 10 → high

    def test_timestamp_parsing(self):
        raw = RawEvent(source_type="splunk", raw={"_time": "2024-01-15T10:23:45Z", "_raw": "test"})
        norm = normalize_event(raw)
        assert norm.timestamp == datetime(2024, 1, 15, 10, 23, 45)

    def test_missing_fields_graceful(self):
        raw = RawEvent(source_type="splunk", raw={"_raw": "bare log line"})
        norm = normalize_event(raw)
        assert norm.message == "bare log line"
        assert norm.severity == Severity.LOW

    def test_to_text_contains_key_fields(self, sample_norm_event):
        text = sample_norm_event.to_text()
        assert "web-server-01" in text
        assert "192.168.1.100" in text
        assert "authentication" in text


class TestChunker:
    def _make_events(self, n: int, start: datetime, gap_minutes: int = 1) -> list[NormEvent]:
        return [
            NormEvent(
                source_type="splunk",
                timestamp=start + timedelta(minutes=i * gap_minutes),
                message=f"event {i}",
                severity=Severity.LOW,
            )
            for i in range(n)
        ]

    def test_single_window(self):
        start = datetime(2024, 1, 15, 10, 0)
        events = self._make_events(10, start, gap_minutes=1)
        chunks = list(chunk_events(events, window_minutes=15))
        assert len(chunks) == 1
        assert len(chunks[0].events) == 10

    def test_multiple_windows(self):
        start = datetime(2024, 1, 15, 10, 0)
        events = self._make_events(40, start, gap_minutes=1)  # 40 min span
        chunks = list(chunk_events(events, window_minutes=15))
        assert len(chunks) >= 2

    def test_max_events_splits_chunk(self):
        start = datetime(2024, 1, 15, 10, 0)
        events = self._make_events(50, start, gap_minutes=1)
        chunks = list(chunk_events(events, window_minutes=60, max_events=20))
        assert all(len(c.events) <= 20 for c in chunks)

    def test_empty_events(self):
        chunks = list(chunk_events([]))
        assert chunks == []

    def test_separate_source_types(self):
        start = datetime(2024, 1, 15, 10, 0)
        splunk_events = self._make_events(5, start)
        wazuh_events = [
            NormEvent(source_type="wazuh", timestamp=start, message="w", severity=Severity.LOW)
            for _ in range(5)
        ]
        chunks = list(chunk_events(splunk_events + wazuh_events, window_minutes=60))
        source_types = {c.source_type for c in chunks}
        assert "splunk" in source_types
        assert "wazuh" in source_types
