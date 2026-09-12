from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from opsguard.data import load_dataset, load_manifest
from opsguard.domain.models import Event
from opsguard.repositories import (
    EventQuery,
    InMemoryEventRepository,
    JsonlEventRepository,
)

ROOT = Path(__file__).parents[1]


def _fixture_paths() -> list[Path]:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    return [ROOT / "datasets" / case["file"] for case in manifest.cases]


def test_jsonl_repository_indexes_all_fixture_events() -> None:
    repository = JsonlEventRepository(_fixture_paths())

    assert len(repository) == 9
    assert len(repository.search(EventQuery(host="web-03"))) == 6
    assert len(repository.search(EventQuery(source="process_network"))) == 3
    assert [event.event_id for event in repository.search(EventQuery(process="bash"))] == [
        "evt-web-002",
        "evt-web-003",
    ]


def test_repository_supports_time_and_entity_filters() -> None:
    repository = JsonlEventRepository(_fixture_paths())
    query = EventQuery(
        start_time=datetime(2026, 9, 10, 2, 14, tzinfo=UTC),
        end_time=datetime(2026, 9, 10, 2, 16, tzinfo=UTC),
        user="deploy",
    )

    assert [event.event_id for event in repository.search(query)] == [
        "evt-ssh-002",
        "evt-ssh-003",
    ]


def test_repository_rejects_conflicting_duplicate_event_ids() -> None:
    event = Event(
        event_id="evt-duplicate",
        timestamp="2026-09-10T00:00:00Z",
        source="linux_audit",
        action="test",
    )
    repository = InMemoryEventRepository([event])

    with pytest.raises(ValueError, match="conflicting event_id"):
        repository.add(event.model_copy(update={"action": "different"}))


def test_query_rejects_invalid_time_range_and_source() -> None:
    with pytest.raises(ValueError, match="start_time"):
        EventQuery(
            start_time="2026-09-11T00:00:00Z",
            end_time="2026-09-10T00:00:00Z",
        )

    with pytest.raises(ValidationError):
        EventQuery(source="not-a-source")


def test_dataset_records_can_be_loaded_into_repository() -> None:
    records = load_dataset(ROOT / "datasets" / "suspicious" / "ssh_persistence.jsonl")
    repository = JsonlEventRepository.from_dataset_records(records)

    assert len(repository) == 3
    assert repository.get("evt-ssh-003") is not None

