"""Append-only feedback store for the local feedback flywheel."""

from __future__ import annotations

from .models import FeedbackRecord


class FeedbackConflictError(ValueError):
    """Raised when one feedback id is reused with different content."""


class InMemoryFeedbackStore:
    def __init__(self) -> None:
        self._records: dict[str, FeedbackRecord] = {}

    def add(self, record: FeedbackRecord) -> None:
        existing = self._records.get(record.feedback_id)
        if existing is not None and existing != record:
            raise FeedbackConflictError(
                f"conflicting feedback_id: {record.feedback_id}"
            )
        self._records[record.feedback_id] = record.model_copy(deep=True)

    def list(
        self,
        rule_id: str | None = None,
        rule_version: int | None = None,
    ) -> list[FeedbackRecord]:
        records = self._records.values()
        if rule_id is not None:
            records = (record for record in records if record.rule_id == rule_id)
        if rule_version is not None:
            records = (
                record for record in records if record.rule_version == rule_version
            )
        return [
            record.model_copy(deep=True)
            for record in sorted(
                records,
                key=lambda item: (item.created_at, item.feedback_id),
            )
        ]
