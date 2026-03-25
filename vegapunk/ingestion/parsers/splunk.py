"""Splunk JSON/CSV export parser."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterator

from vegapunk.ingestion.parsers.base import BaseParser
from vegapunk.models import RawEvent


class SplunkParser(BaseParser):
    source_type = "splunk"

    def parse_file(self, path: Path) -> Iterator[RawEvent]:
        suffix = path.suffix.lower()
        if suffix == ".json":
            yield from self._parse_json(path)
        elif suffix == ".csv":
            yield from self._parse_csv(path)
        else:
            raise ValueError(f"Unsupported Splunk export format: {suffix}")

    def _parse_json(self, path: Path) -> Iterator[RawEvent]:
        with path.open() as f:
            data = json.load(f)
        records = data if isinstance(data, list) else data.get("results", [data])
        for record in records:
            yield self.parse_record(record)

    def _parse_csv(self, path: Path) -> Iterator[RawEvent]:
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                yield self.parse_record(dict(row))

    def parse_record(self, record: dict) -> RawEvent:
        return RawEvent(source_type=self.source_type, raw=record)
