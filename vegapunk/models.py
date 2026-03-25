"""
Shared domain models.

RawEvent  — parser output, SIEM-specific fields preserved.
NormEvent — ECS-normalized event, SIEM-agnostic.
LogChunk  — time-window bundle of NormEvents, the unit ingested into storage.
TriageResult — output of the triage agent.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RawEvent(BaseModel):
    """Raw parsed event before normalization."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_type: str                    # splunk | elastic | wazuh
    raw: dict[str, Any]                 # original fields
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class NormEvent(BaseModel):
    """ECS-normalized event — SIEM-agnostic."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    source_type: str
    timestamp: datetime
    message: str
    host: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    process: str | None = None
    event_category: str | None = None   # e.g. authentication, network, file
    event_action: str | None = None     # e.g. logon, connection, delete
    severity: Severity = Severity.LOW
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    def to_text(self) -> str:
        """Human-readable representation for embedding."""
        parts = [
            f"[{self.timestamp.isoformat()}]",
            f"host={self.host or 'unknown'}",
            f"user={self.user or '-'}",
            f"src={self.source_ip or '-'}",
            f"dst={self.dest_ip or '-'}",
            f"category={self.event_category or '-'}",
            f"action={self.event_action or '-'}",
            f"severity={self.severity.value}",
            self.message,
        ]
        return " | ".join(parts)


class LogChunk(BaseModel):
    """Time-window bundle of normalized events."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    window_start: datetime
    window_end: datetime
    source_type: str
    events: list[NormEvent]

    @property
    def summary_text(self) -> str:
        lines = [f"Time window: {self.window_start} → {self.window_end}"]
        lines += [e.to_text() for e in self.events]
        return "\n".join(lines)


class TriageResult(BaseModel):
    """Output of the Haiku triage agent."""
    event_id: str
    severity: Severity
    confidence: float               # 0-1, escalate to Sonnet if < threshold
    summary: str
    needs_deep_analysis: bool
    mitre_tactics: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Output of the Sonnet analyst agent."""
    event_id: str
    severity: Severity
    summary: str
    root_cause: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
