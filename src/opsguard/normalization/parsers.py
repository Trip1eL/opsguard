from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opsguard.domain.models import Event, EventSource


class EventNormalizationError(ValueError):
    """Raised when a raw event cannot be normalized into the domain model."""


class EventParser:
    source: EventSource

    def parse(self, payload: Mapping[str, Any]) -> Event:
        if payload.get("source") != self.source.value:
            raise EventNormalizationError(
                f"parser {self.source.value!r} received source={payload.get('source')!r}"
            )
        try:
            return Event.model_validate(dict(payload))
        except ValueError as exc:
            raise EventNormalizationError(
                f"invalid {self.source.value} event: {exc}"
            ) from exc


class LinuxAuditParser(EventParser):
    source = EventSource.LINUX_AUDIT


class WebAccessParser(EventParser):
    source = EventSource.WEB_ACCESS


class ProcessNetworkParser(EventParser):
    source = EventSource.PROCESS_NETWORK


class EventNormalizer:
    """Dispatch source-specific payloads to the corresponding parser."""

    def __init__(self) -> None:
        self._parsers: dict[EventSource, EventParser] = {
            EventSource.LINUX_AUDIT: LinuxAuditParser(),
            EventSource.WEB_ACCESS: WebAccessParser(),
            EventSource.PROCESS_NETWORK: ProcessNetworkParser(),
        }

    def normalize(self, payload: Mapping[str, Any]) -> Event:
        source_value = payload.get("source")
        try:
            source = EventSource(source_value)
        except ValueError as exc:
            raise EventNormalizationError(
                f"unknown event source: {source_value!r}"
            ) from exc
        return self._parsers[source].parse(payload)


def normalize_event(payload: Mapping[str, Any]) -> Event:
    return EventNormalizer().normalize(payload)

