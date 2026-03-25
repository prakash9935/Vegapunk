"""Wazuh alert JSON export parser."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from vegapunk.ingestion.parsers.base import BaseParser
from vegapunk.models import RawEvent


class WazuhParser(BaseParser):
    source_type = "wazuh"

    def parse_file(self, path: Path) -> Iterator[RawEvent]:
        with path.open() as f:
            # Wazuh exports one JSON object per line (NDJSON) or a JSON array
            content = f.read().strip()

        if content.startswith("["):
            records = json.loads(content)
        else:
            records = [json.loads(line) for line in content.splitlines() if line.strip()]

        for record in records:
            yield self.parse_record(record)

    def parse_record(self, record: dict) -> RawEvent:
        return RawEvent(source_type=self.source_type, raw=record)
