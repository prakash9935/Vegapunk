"""
Wazuh Cloud connector — OpenSearch Dashboards internal search API.

Ports 55000 (Manager API) and 9200 (OpenSearch) are blocked on Wazuh Cloud
free tier. Instead, we go through the same HTTPS endpoint (443) the dashboard
UI uses.

Authentication:
  The OpenSearch security plugin accepts HTTP Basic Auth on every request —
  no session handshake or login endpoint required. Credentials are sent via
  the Authorization header on every call.

Endpoint confirmed from browser Network tab:
  POST /internal/search/opensearch-with-long-numerals
  index: wazuh-alerts  (not wazuh-alerts-*)
"""
from __future__ import annotations

import asyncio
import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from vegapunk.config import settings
from vegapunk.models import RawEvent

logger = logging.getLogger(__name__)

_SEARCH_PATH = "/internal/search/opensearch-with-long-numerals"
_INDEX = "wazuh-alerts"


def _basic_auth(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _osd_headers() -> dict[str, str]:
    return {
        "osd-xsrf": "osd-fetch",
        "osd-version": "2.19.4",
        "Content-Type": "application/json",
        "Authorization": _basic_auth(settings.wazuh_username, settings.wazuh_password),
    }


class WazuhCloudConnector:
    """
    Polls Wazuh Cloud for new alerts via the OpenSearch Dashboards
    internal search API (port 443, same as the dashboard UI).

    Usage:
        connector = WazuhCloudConnector()
        async for batch in connector.stream(interval_seconds=60):
            norm = [normalize_event(r) for r in batch]
    """

    def __init__(self) -> None:
        self._base = str(settings.wazuh_cloud_url).rstrip("/")
        # Start 5 minutes in the past so the first poll catches recent alerts
        self._last_seen: datetime = datetime.now(timezone.utc) - timedelta(minutes=5)
        self._client = httpx.AsyncClient(
            verify=settings.wazuh_verify_ssl,
            headers=_osd_headers(),
            follow_redirects=True,
            timeout=30,
        )

    # ── Search ───────────────────────────────────────────────────────────────

    async def _search(self, since: datetime) -> list[dict[str, Any]]:
        """
        Query wazuh-alerts index for alerts newer than `since`.
        Returns a list of raw alert dicts (_source from each hit).
        """
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        body = {
            "params": {
                "index": _INDEX,
                "body": {
                    "sort": [{"timestamp": {"order": "asc", "unmapped_type": "boolean"}}],
                    "size": 500,
                    "_source": {"excludes": ["@timestamp"]},
                    "stored_fields": ["*"],
                    "query": {
                        "bool": {
                            "filter": [
                                {"match_all": {}},
                                {
                                    "range": {
                                        "timestamp": {
                                            "gt": since_str,
                                            "format": "strict_date_optional_time",
                                        }
                                    }
                                },
                            ]
                        }
                    },
                },
            }
        }
        resp = await self._client.post(f"{self._base}{_SEARCH_PATH}", json=body)
        resp.raise_for_status()
        data = resp.json()
        # OpenSearch Dashboards wraps the ES response; handle both formats
        raw = data.get("rawResponse", data)
        hits = raw.get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]

    # ── Stream ───────────────────────────────────────────────────────────────

    async def stream(self, interval_seconds: int = 60):
        """
        Async generator — yields batches of RawEvents on each poll interval.
        """
        logger.info(
            "Wazuh Cloud connector started — polling every %ds", interval_seconds
        )
        while True:
            try:
                poll_start = datetime.now(timezone.utc)
                alerts = await self._search(self._last_seen)

                if alerts:
                    logger.info("Fetched %d new alerts from Wazuh Cloud.", len(alerts))
                    self._last_seen = poll_start
                    yield [RawEvent(source_type="wazuh", raw=a) for a in alerts]
                else:
                    logger.debug("No new alerts since %s.", self._last_seen.isoformat())

            except httpx.RequestError as e:
                logger.error(
                    "Connection error: %s — retrying in %ds", e, interval_seconds
                )

            await asyncio.sleep(interval_seconds)

    # ── Health check ─────────────────────────────────────────────────────────

    async def health_check(self) -> dict[str, Any]:
        """Count alerts from the last 24 hours to verify connectivity."""
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            alerts = await self._search(since)
            return {"status": "ok", "alerts_last_24h": len(alerts)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def aclose(self) -> None:
        await self._client.aclose()
