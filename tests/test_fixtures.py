from pathlib import Path

from opsguard.data import load_dataset, load_manifest
from opsguard.domain.models import EventSource

ROOT = Path(__file__).parents[1]


def test_manifest_lists_three_reproducible_cases() -> None:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")

    assert len(manifest.cases) == 3
    assert {case["label"] for case in manifest.cases} == {"suspicious", "benign"}


def test_all_fixture_records_validate_and_keep_raw_traceability() -> None:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    records = []
    for case in manifest.cases:
        records.extend(load_dataset(ROOT / "datasets" / case["file"]))

    assert len(records) == 9
    assert {record.event.source for record in records} == {
        EventSource.LINUX_AUDIT,
        EventSource.WEB_ACCESS,
        EventSource.PROCESS_NETWORK,
    }
    assert all(record.event.raw_log for record in records)
    assert all(record.event.event_id.startswith("evt-") for record in records)
    assert {record.case_id for record in records} == {
        "case-ssh-persistence-001",
        "case-web-child-process-001",
        "case-release-window-001",
    }


def test_suspicious_and_benign_case_labels_are_stable() -> None:
    suspicious = load_dataset(
        ROOT / "datasets" / "suspicious" / "ssh_persistence.jsonl"
    )
    benign = load_dataset(ROOT / "datasets" / "normal" / "release_window.jsonl")

    assert {record.event_label for record in suspicious} == {"suspicious"}
    assert {record.event_label for record in benign} == {"benign"}
    assert "persistence" in suspicious[-1].expected_stages
    assert benign[0].expected_stages == ["正常运维"]
