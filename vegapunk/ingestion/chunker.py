"""
Time-window chunker.

Groups a stream of NormEvents into LogChunks by sliding time windows.
This keeps context together for the RAG retriever and agent analysis.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterator

from vegapunk.config import settings
from vegapunk.models import LogChunk, NormEvent


def chunk_events(
    events: list[NormEvent],
    window_minutes: int | None = None,
    max_events: int | None = None,
) -> Iterator[LogChunk]:
    """
    Partition events into time-window LogChunks.

    Events are first bucketed by source_type, then grouped into
    fixed-size time windows. Chunks exceeding max_events are split.
    """
    window_minutes = window_minutes or settings.chunk_window_minutes
    max_events = max_events or settings.max_chunk_events
    delta = timedelta(minutes=window_minutes)

    # Group by source type to keep SIEM streams separate
    by_source: dict[str, list[NormEvent]] = defaultdict(list)
    for ev in events:
        by_source[ev.source_type].append(ev)

    for source_type, source_events in by_source.items():
        sorted_events = sorted(source_events, key=lambda e: e.timestamp)
        if not sorted_events:
            continue

        window_start = sorted_events[0].timestamp
        window_end = window_start + delta
        bucket: list[NormEvent] = []

        for event in sorted_events:
            if event.timestamp > window_end or len(bucket) >= max_events:
                if bucket:
                    yield _make_chunk(source_type, window_start, window_end, bucket)
                # Advance window
                while event.timestamp > window_end:
                    window_start = window_end
                    window_end = window_start + delta
                bucket = [event]
            else:
                bucket.append(event)

        if bucket:
            yield _make_chunk(source_type, window_start, window_end, bucket)


def _make_chunk(
    source_type: str,
    window_start: datetime,
    window_end: datetime,
    events: list[NormEvent],
) -> LogChunk:
    return LogChunk(
        window_start=window_start,
        window_end=min(window_end, events[-1].timestamp),
        source_type=source_type,
        events=list(events),
    )
