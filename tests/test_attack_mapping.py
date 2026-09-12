from pathlib import Path

from opsguard.attack import AttackTechniqueMapper, TechniqueCatalog
from opsguard.correlation import BehaviorCorrelator
from opsguard.data import load_dataset, load_manifest
from opsguard.detection import DetectionEngine
from opsguard.repositories import JsonlEventRepository

ROOT = Path(__file__).parents[1]
CATALOG = TechniqueCatalog.from_json(ROOT / "knowledge" / "attack" / "techniques.json")


def _repository() -> JsonlEventRepository:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    return JsonlEventRepository([ROOT / "datasets" / item["file"] for item in manifest.cases])


def test_catalog_is_versioned_and_contains_fixture_techniques() -> None:
    ids = {item.technique_id for item in CATALOG.techniques}
    assert CATALOG.version.startswith("attack-subset-")
    assert {"T1021.004", "T1053.003", "T1105", "T1505.003"} <= ids


def test_ssh_chain_maps_to_evidence_backed_techniques() -> None:
    repository = _repository()
    events = repository.search()
    alert = next(item for item in DetectionEngine().detect(events) if item.alert_id.startswith("alert-scheduled_task"))
    result = BehaviorCorrelator().correlate(alert, events)
    mapped = AttackTechniqueMapper(CATALOG).map_chain(result.chain, events)
    mapping_ids = {item.technique_id for item in mapped.mappings}
    assert {"T1021.004", "T1053.003", "T1105"} <= mapping_ids
    assert all(item.evidence for item in mapped.mappings)
    assert all(event_id in result.chain.event_ids for item in mapped.mappings for evidence in item.evidence for event_id in evidence.event_ids)


def test_web_chain_maps_web_shell_and_web_protocols() -> None:
    repository = _repository()
    events = repository.search()
    alert = next(item for item in DetectionEngine().detect(events) if item.alert_id.startswith("alert-web_child"))
    result = BehaviorCorrelator().correlate(alert, events)
    mapped = AttackTechniqueMapper(CATALOG).map_chain(result.chain, events)
    assert {"T1505.003", "T1059.004", "T1071.001"} <= {item.technique_id for item in mapped.mappings}


def test_coverage_report_identifies_missing_requested_technique() -> None:
    repository = _repository()
    events = repository.search()
    alert = DetectionEngine().detect(events)[0]
    result = BehaviorCorrelator().correlate(alert, events)
    mapped = AttackTechniqueMapper(CATALOG).map_chain(result.chain, events)
    report = AttackTechniqueMapper(CATALOG).coverage(mapped, ["T1021.004", "T9999.999"])
    assert report.uncovered_technique_ids == ["T9999.999"]
    assert report.coverage_ratio == 0.5


def test_benign_release_events_do_not_map_to_attack_techniques() -> None:
    events = [record.event for record in load_dataset(ROOT / "datasets" / "normal" / "release_window.jsonl")]
    assert AttackTechniqueMapper(CATALOG).map_events(events) == []

