"""Abstract base parser — all SIEM parsers implement this interface."""
from __future__ import annotations

import abc
from pathlib import Path
from typing import Iterator

from vegapunk.models import RawEvent


class BaseParser(abc.ABC):
    """Parse a SIEM export file into a stream of RawEvents."""

    @abc.abstractmethod
    def parse_file(self, path: Path) -> Iterator[RawEvent]:
        """Yield one RawEvent per log record."""

    @abc.abstractmethod
    def parse_record(self, record: dict) -> RawEvent:
        """Convert a single raw dict into a RawEvent."""

    @property
    @abc.abstractmethod
    def source_type(self) -> str:
        """Identifier for this SIEM source (e.g. 'splunk')."""
