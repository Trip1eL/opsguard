from pathlib import Path

from opsguard.data import load_dataset, load_manifest
from opsguard.detection import DetectionEngine
from opsguard.domain.cases import AlertSeverity
from opsguard.repositories import JsonlEventRepository

ROOT = Path(__file__).parents[1]


def _repository() -> JsonlEventRepository:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    paths = [ROOT / "datasets" / item["file"] for item in manifest.cases]
    return JsonlEventRepository(paths)


def test_detection_engine_finds_expected_suspicious_behaviors() -> None:
    alerts = DetectionEngine().detect(_repository().search())
    titles = {alert.title for alert in alerts}

    assert "Successful SSH login from a new source" in titles
    assert "Scheduled task executes a suspicious command" in titles
    assert "Web process spawned an interpreter" in titles
    assert "Process connected to an external network destination" in titles


def test_detection_alerts_have_traceable_evidence_and_valid_scores() -> None:
    alerts = DetectionEngine().detect(_repository().search())

    assert alerts
    assert all(0 <= alert.risk_score <= 1 for alert in alerts)
    assert all(alert.event_ids for alert in alerts)
    assert all(alert.evidence for alert in alerts)
    assert all(
        set(alert.event_ids) == set(alert.evidence[0].event_ids) for alert in alerts
    )
    assert any(alert.severity == AlertSeverity.HIGH for alert in alerts)


def test_normal_release_window_has_no_alerts() -> None:
    events = [
        record.event
        for record in load_dataset(ROOT / "datasets" / "normal" / "release_window.jsonl")
    ]

    assert DetectionEngine().detect(events) == []


def test_detection_is_deterministic_for_same_event_sequence() -> None:
    events = _repository().search()
    first = DetectionEngine().detect(events)
    second = DetectionEngine().detect(events)

    assert [alert.model_dump() for alert in first] == [alert.model_dump() for alert in second]

