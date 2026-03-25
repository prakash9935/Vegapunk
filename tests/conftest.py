"""Shared test fixtures."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from vegapunk.models import NormEvent, RawEvent, Severity


@pytest.fixture
def sample_raw_splunk() -> dict:
    return {
        "_time": "2024-01-15T10:23:45Z",
        "_raw": "Failed password for root from 192.168.1.100 port 22 ssh2",
        "host": "web-server-01",
        "src_ip": "192.168.1.100",
        "user": "root",
        "sourcetype": "authentication",
        "action": "failure",
        "severity": "high",
    }


@pytest.fixture
def sample_raw_wazuh() -> dict:
    return {
        "timestamp": "2024-01-15T10:23:45Z",
        "rule": {"description": "SSH brute force attack", "level": "10", "groups": ["authentication_failures"]},
        "agent": {"name": "web-server-01"},
        "data": {"srcip": "192.168.1.100", "dstuser": "root"},
        "full_log": "Failed password for root from 192.168.1.100",
    }


@pytest.fixture
def sample_norm_event() -> NormEvent:
    return NormEvent(
        source_type="splunk",
        timestamp=datetime(2024, 1, 15, 10, 23, 45),
        message="Failed password for root from 192.168.1.100",
        host="web-server-01",
        source_ip="192.168.1.100",
        user="root",
        event_category="authentication",
        event_action="failure",
        severity=Severity.HIGH,
    )


@pytest.fixture
def splunk_json_file(sample_raw_splunk, tmp_path) -> Path:
    path = tmp_path / "splunk_export.json"
    path.write_text(json.dumps([sample_raw_splunk, sample_raw_splunk]))
    return path


@pytest.fixture
def wazuh_ndjson_file(sample_raw_wazuh, tmp_path) -> Path:
    path = tmp_path / "wazuh_alerts.json"
    path.write_text(json.dumps([sample_raw_wazuh]))
    return path
