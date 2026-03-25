"""
Triage Agent — Claude Haiku.

Fast, cheap first-pass classification of every incoming event.
Produces a TriageResult with severity, confidence, and MITRE tactics.
If confidence < threshold or severity >= high, escalates to AnalystAgent.
"""
from __future__ import annotations

import json
import logging

from anthropic import Anthropic

from vegapunk.config import settings
from vegapunk.models import NormEvent, Severity, TriageResult
from vegapunk.prompts.triage import TRIAGE_PROMPT
from vegapunk.storage.manager import StorageManager

logger = logging.getLogger(__name__)


def _extract_json(text: str) -> str:
    """Pull the first {...} block out of an LLM response, stripping any markdown fences."""
    start, end = text.find("{"), text.rfind("}") + 1
    return text[start:end] if start != -1 and end > start else text


class TriageAgent:
    """Haiku-powered triage — optimized for speed and cost."""

    def __init__(self, storage: StorageManager) -> None:
        self._storage = storage
        self._client = Anthropic(api_key=settings.anthropic_api_key)

    def triage(self, event: NormEvent) -> TriageResult:
        """Classify a single event. Returns TriageResult."""
        similar = self._storage.semantic_search(event.to_text(), n=3)
        similar_text = "\n".join(r["document"][:200] for r in similar) or "None"

        human_msg = TRIAGE_PROMPT["human"].format(
            event_id=event.id,
            event_text=event.to_text(),
            similar_events=similar_text,
        )

        response = self._client.messages.create(
            model=settings.triage_model,
            max_tokens=512,
            system=TRIAGE_PROMPT["system"],
            messages=[{"role": "user", "content": human_msg}],
        )

        raw_json = _extract_json(response.content[0].text.strip())
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.warning("Triage JSON parse failed for event %s", event.id)
            data = {
                "severity": "medium",
                "confidence": 0.5,
                "summary": "Triage parse failed — manual review needed",
                "needs_deep_analysis": True,
                "mitre_tactics": [],
            }

        needs_deep = (
            data.get("needs_deep_analysis", False)
            or data.get("confidence", 1.0) < settings.triage_confidence_threshold
            or data.get("severity") in ("high", "critical")
        )

        return TriageResult(
            event_id=event.id,
            severity=Severity(data.get("severity", "low")),
            confidence=float(data.get("confidence", 0.5)),
            summary=data.get("summary", ""),
            needs_deep_analysis=needs_deep,
            mitre_tactics=data.get("mitre_tactics", []),
        )
