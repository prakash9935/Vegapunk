"""
ECS (Elastic Common Schema) normalizer.

Maps SIEM-specific field names to a common NormEvent.
Each SIEM has its own field mapping; the fallback extracts best-effort values.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from vegapunk.models import NormEvent, RawEvent, Severity

# ── Field-mapping tables ────────────────────────────────────────────────────

_SPLUNK_MAP = {
    "timestamp": ["_time", "timestamp", "time"],
    "message":   ["_raw", "message", "msg", "event"],
    "host":      ["host", "hostname", "src_host"],
    "source_ip": ["src_ip", "src", "sourceIp", "client_ip"],
    "dest_ip":   ["dest_ip", "dest", "dst", "destinationIp"],
    "user":      ["user", "username", "accountName"],
    "process":   ["process", "process_name", "Image"],
    "event_category": ["category", "event_category", "sourcetype"],
    "event_action":   ["action", "event_action", "EventCode"],
}

_ELASTIC_MAP = {
    "timestamp": ["@timestamp", "timestamp"],
    "message":   ["message", "log.original"],
    "host":      ["host.name", "host.hostname"],
    "source_ip": ["source.ip", "client.ip"],
    "dest_ip":   ["destination.ip", "server.ip"],
    "user":      ["user.name", "related.user"],
    "process":   ["process.name", "process.executable"],
    "event_category": ["event.category"],
    "event_action":   ["event.action", "event.type"],
}

_WAZUH_MAP = {
    "timestamp": ["timestamp", "@timestamp"],
    "message":   ["full_log", "data.win.system.message", "rule.description"],
    "host":      ["agent.name", "manager.name"],
    "source_ip": ["data.srcip", "data.win.eventdata.ipAddress"],
    "dest_ip":   ["data.dstip"],
    "user":      ["data.win.eventdata.targetUserName", "data.dstuser"],
    "process":   ["data.win.eventdata.processName", "data.srcUser"],
    "event_category": ["rule.groups"],
    "event_action":   ["data.win.system.eventID", "rule.id"],
}

_SEVERITY_MAP = {
    "splunk": {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL},
    "elastic": {"1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH, "4": Severity.CRITICAL},
    "wazuh": {  # Wazuh uses numeric levels 0-15
        **{str(i): Severity.LOW for i in range(4)},
        **{str(i): Severity.MEDIUM for i in range(4, 8)},
        **{str(i): Severity.HIGH for i in range(8, 12)},
        **{str(i): Severity.CRITICAL for i in range(12, 16)},
    },
}

_MAPS = {"splunk": _SPLUNK_MAP, "elastic": _ELASTIC_MAP, "wazuh": _WAZUH_MAP}


def _get(raw: dict[str, Any], candidates: list[str]) -> Any:
    """Return the first matching value from a list of candidate field names."""
    for key in candidates:
        # Support dot-notation for nested dicts
        parts = key.split(".")
        val = raw
        try:
            for part in parts:
                val = val[part]
            if val is not None and val != "":
                return val
        except (KeyError, TypeError):
            continue
    return None


def _parse_timestamp(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    if isinstance(val, (int, float)):
        return datetime.utcfromtimestamp(float(val))
    if isinstance(val, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
    return datetime.utcnow()


def normalize_event(raw_event: RawEvent) -> NormEvent:
    """Map a RawEvent to a SIEM-agnostic NormEvent."""
    raw = raw_event.raw
    field_map = _MAPS.get(raw_event.source_type, _SPLUNK_MAP)

    timestamp_raw = _get(raw, field_map["timestamp"])
    timestamp = _parse_timestamp(timestamp_raw) if timestamp_raw else raw_event.ingested_at

    message = _get(raw, field_map["message"]) or str(raw)[:500]
    category_raw = _get(raw, field_map["event_category"])

    # Severity: try source-specific field, then generic
    sev_raw = str(_get(raw, ["severity", "level", "priority", "rule.level"]) or "").lower()
    sev_lookup = _SEVERITY_MAP.get(raw_event.source_type, {})
    severity = sev_lookup.get(sev_raw, Severity.LOW)

    tags: list[str] = []
    if isinstance(category_raw, list):
        tags = [str(c) for c in category_raw]
        category_raw = tags[0] if tags else None

    return NormEvent(
        id=raw_event.id,
        source_type=raw_event.source_type,
        timestamp=timestamp,
        message=str(message),
        host=str(_get(raw, field_map["host"]) or ""),
        source_ip=str(_get(raw, field_map["source_ip"]) or ""),
        dest_ip=str(_get(raw, field_map["dest_ip"]) or ""),
        user=str(_get(raw, field_map["user"]) or ""),
        process=str(_get(raw, field_map["process"]) or ""),
        event_category=str(category_raw) if category_raw else None,
        event_action=str(_get(raw, field_map["event_action"]) or ""),
        severity=severity,
        tags=tags,
        raw=raw,
    )
