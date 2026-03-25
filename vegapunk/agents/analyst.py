"""
Analyst Agent — Claude Sonnet.

Deep forensic analysis, MITRE ATT&CK technique mapping, and remediation.
Only invoked when triage escalates (high severity or low confidence).
Uses LangChain ReAct agent with VectorSearch + SQL + MITRE tools.
"""
from __future__ import annotations

import json
import logging

from anthropic import Anthropic

from vegapunk.config import settings
from vegapunk.models import AnalysisResult, NormEvent, Severity, TriageResult
from vegapunk.prompts.analysis import ANALYSIS_PROMPT
from vegapunk.storage.manager import StorageManager

logger = logging.getLogger(__name__)


def _extract_json(text: str) -> str:
    """Pull the first {...} block out of an LLM response, stripping any markdown fences."""
    start, end = text.find("{"), text.rfind("}") + 1
    return text[start:end] if start != -1 and end > start else text


class AnalystAgent:
    """Sonnet-powered deep analyst — invoked only on escalation."""

    def __init__(self, storage: StorageManager) -> None:
        self._storage = storage
        self._client = Anthropic(api_key=settings.anthropic_api_key)

    def analyze(self, event: NormEvent, triage: TriageResult) -> AnalysisResult:
        """Deep analysis of an escalated event."""
        similar = self._storage.semantic_search(event.to_text(), n=6)
        similar_text = "\n---\n".join(r["document"][:300] for r in similar) or "None"

        # Fetch related events by source IP or host
        sql_context = self._fetch_sql_context(event)

        human_msg = ANALYSIS_PROMPT["human"].format(
            event_id=event.id,
            triage_summary=f"Severity: {triage.severity.value}, "
                           f"Confidence: {triage.confidence:.0%}\n{triage.summary}",
            event_text=event.to_text(),
            similar_events=similar_text,
            sql_context=sql_context,
        )

        response = self._client.messages.create(
            model=settings.analyst_model,
            max_tokens=1024,
            system=ANALYSIS_PROMPT["system"],
            messages=[{"role": "user", "content": human_msg}],
        )

        raw_json = _extract_json(response.content[0].text.strip())
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("Analyst JSON parse failed for event %s", event.id)
            data = {
                "severity": triage.severity.value,
                "summary": "Analysis parse failed — see raw logs",
                "root_cause": None,
                "mitre_techniques": [],
                "recommended_actions": ["Manual review required"],
                "related_event_ids": [],
            }

        return AnalysisResult(
            event_id=event.id,
            severity=Severity(data.get("severity", triage.severity.value)),
            summary=data.get("summary", ""),
            root_cause=data.get("root_cause"),
            mitre_techniques=data.get("mitre_techniques", []),
            recommended_actions=data.get("recommended_actions", []),
            related_event_ids=data.get("related_event_ids", []),
        )

    def _fetch_sql_context(self, event: NormEvent) -> str:
        """Pull related events from SQLite for richer context."""
        parts = []
        if event.source_ip:
            rows = self._storage.sql_query(
                "SELECT id, timestamp, message, severity FROM events "
                "WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 10",
                (event.source_ip,),
            )
            if rows:
                parts.append(f"Events from same source IP ({event.source_ip}):")
                parts += [f"  {r['timestamp']} [{r['severity']}] {r['message'][:100]}" for r in rows]

        if event.user:
            rows = self._storage.sql_query(
                "SELECT id, timestamp, message, severity FROM events "
                "WHERE username = ? ORDER BY timestamp DESC LIMIT 10",
                (event.user,),
            )
            if rows:
                parts.append(f"\nEvents from same user ({event.user}):")
                parts += [f"  {r['timestamp']} [{r['severity']}] {r['message'][:100]}" for r in rows]

        return "\n".join(parts) if parts else "No additional SQL context."
