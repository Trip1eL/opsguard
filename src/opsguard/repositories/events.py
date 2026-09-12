from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, model_validator

from opsguard.data.fixtures import DatasetRecord
from opsguard.domain.models import Event, EventSource
from opsguard.normalization.parsers import EventNormalizationError, EventNormalizer


class RepositoryError(ValueError):
    """Raised for invalid or conflicting repository operations."""


class EventQuery(BaseModel):
    start_time: datetime | None = None
    end_time: datetime | None = None
    event_ids: set[str] = Field(default_factory=set)
    source: EventSource | None = None
    host: str | None = None
    user: str | None = None
    process: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    domain: str | None = None
    action: str | None = None

    @model_validator(mode="after")
    def validate_time_range(self) -> EventQuery:
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must be earlier than or equal to end_time")
        return self


class EventRepository(Protocol):
    def add(self, event: Event) -> None: ...

    def add_many(self, events: Iterable[Event]) -> None: ...

    def get(self, event_id: str) -> Event | None: ...

    def search(self, query: EventQuery | None = None) -> list[Event]: ...

    def __len__(self) -> int: ...


class InMemoryEventRepository:
    def __init__(self, events: Iterable[Event] = ()) -> None:
        self._events: dict[str, Event] = {}
        self.add_many(events)

    def add(self, event: Event) -> None:
        existing = self._events.get(event.event_id)
        if existing is not None and existing != event:
            raise RepositoryError(f"conflicting event_id: {event.event_id}")
        self._events[event.event_id] = event

    def add_many(self, events: Iterable[Event]) -> None:
        for event in events:
            self.add(event)

    def get(self, event_id: str) -> Event | None:
        return self._events.get(event_id)

    def search(self, query: EventQuery | None = None) -> list[Event]:
        query = query or EventQuery()
        results = [event for event in self._events.values() if self._matches(event, query)]
        return sorted(results, key=lambda event: (event.timestamp, event.event_id))

    def __len__(self) -> int:
        return len(self._events)

    @staticmethod
    def _matches(event: Event, query: EventQuery) -> bool:
        if query.event_ids and event.event_id not in query.event_ids:
            return False
        if query.start_time and event.timestamp < query.start_time:
            return False
        if query.end_time and event.timestamp > query.end_time:
            return False
        for field in (
            "source",
            "host",
            "user",
            "process",
            "src_ip",
            "dst_ip",
            "domain",
            "action",
        ):
            expected = getattr(query, field)
            if expected is not None and getattr(event, field) != expected:
                return False
        return True


class JsonlEventRepository(InMemoryEventRepository):
    """File adapter that normalizes JSONL event payloads before indexing them."""

    def __init__(
        self,
        paths: Sequence[Path],
        normalizer: EventNormalizer | None = None,
    ) -> None:
        self._normalizer = normalizer or EventNormalizer()
        super().__init__(self._read_paths(paths))

    @classmethod
    def from_dataset_records(
        cls,
        records: Iterable[DatasetRecord],
        normalizer: EventNormalizer | None = None,
    ) -> JsonlEventRepository:
        repository = cls.__new__(cls)
        repository._normalizer = normalizer or EventNormalizer()
        repository._events = {}
        repository.add_many(record.event for record in records)
        return repository

    def _read_paths(self, paths: Sequence[Path]) -> Iterable[Event]:
        for path in paths:
            yield from self._read_path(path)

    def _read_path(self, path: Path) -> Iterable[Event]:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if not raw_line.strip():
                    continue
                try:
                    payload = json.loads(raw_line)
                    if "event" in payload:
                        payload = payload["event"]
                    yield self._normalizer.normalize(payload)
                except (json.JSONDecodeError, EventNormalizationError, TypeError) as exc:
                    raise RepositoryError(
                        f"invalid event at {path}:{line_number}: {exc}"
                    ) from exc

