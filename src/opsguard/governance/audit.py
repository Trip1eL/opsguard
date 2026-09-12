"""Append-only in-memory audit adapter used by the local governance workflow."""

from __future__ import annotations

from collections.abc import Iterable

from .models import AuditRecord


class InMemoryAuditLog:
    def __init__(self, records: Iterable[AuditRecord] = ()) -> None:
        self._records = list(records)

    def append(self, record: AuditRecord) -> None:
        self._records.append(record.model_copy(deep=True))

    def records(self, scope_id: str | None = None) -> list[AuditRecord]:
        records = self._records
        if scope_id is not None:
            records = [record for record in records if record.scope_id == scope_id]
        return [record.model_copy(deep=True) for record in records]
