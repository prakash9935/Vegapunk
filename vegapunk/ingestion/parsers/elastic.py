"""Elasticsearch / OpenSearch JSON export parser."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from vegapunk.ingestion.parsers.base import BaseParser
from vegapunk.models import RawEvent


class ElasticParser(BaseParser):
    source_type = "elastic"

    def parse_file(self, path: Path) -> Iterator[RawEvent]:
        with path.open() as f:
            data = json.load(f)

        # Support both raw hits array and ES search response envelope
        if isinstance(data, list):
            records = data
        elif "hits" in data:
            records = [h["_source"] for h in data["hits"].get("hits", [])]
        else:
            records = [data]

        for record in records:
            yield self.parse_record(record)

    def parse_record(self, record: dict) -> RawEvent:
        return RawEvent(source_type=self.source_type, raw=record)
