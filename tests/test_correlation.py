from pathlib import Path

from opsguard.correlation import (
    BehaviorCorrelator,
    GraphNodeKind,
    InMemoryBehaviorGraph,
    Neo4jBehaviorGraphAdapter,
)
from opsguard.data import load_manifest
from opsguard.detection import DetectionEngine
from opsguard.repositories import JsonlEventRepository

ROOT = Path(__file__).parents[1]


def _repository() -> JsonlEventRepository:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    return JsonlEventRepository([ROOT / "datasets" / item["file"] for item in manifest.cases])


def test_correlator_reconstructs_ssh_persistence_chain() -> None:
    repository = _repository()
    alerts = DetectionEngine().detect(repository.search())
    alert = next(item for item in alerts if item.alert_id.startswith("alert-scheduled_task"))

    result = BehaviorCorrelator().correlate(alert, repository.search())

    assert result.chain.event_ids == ["evt-ssh-001", "evt-ssh-002", "evt-ssh-003"]
    assert result.chain.stages == ["initial_access", "execution", "persistence"]
    assert any(edge.relation == "LEADS_TO" for edge in result.graph.edges)
    assert any(node.kind == GraphNodeKind.HOST for node in result.graph.nodes)


def test_in_memory_graph_supports_entity_relationship_queries() -> None:
    repository = _repository()
    alerts = DetectionEngine().detect(repository.search())
    alert = next(item for item in alerts if item.alert_id.startswith("alert-web_child"))
    result = BehaviorCorrelator().correlate(alert, repository.search())

    graph = InMemoryBehaviorGraph()
    graph.upsert(result.graph)
    related = graph.related("event:evt-web-002")

    assert "process:bash" in {node.node_id for node in related}
    assert "host:api-02" in {node.node_id for node in related}
    assert any(edge.relation == "SPAWNED" for edge in graph.edge_list())


def test_correlator_rejects_alert_with_missing_anchor_event() -> None:
    repository = _repository()
    alerts = DetectionEngine().detect(repository.search())
    alert = alerts[0].model_copy(update={"event_ids": ["evt-missing"]})

    try:
        BehaviorCorrelator().correlate(alert, repository.search())
    except ValueError as exc:
        assert "not found" in str(exc)
    else:
        raise AssertionError("missing anchor event should be rejected")


def test_neo4j_adapter_can_render_graph_upsert_statements_without_driver() -> None:
    repository = _repository()
    alert = DetectionEngine().detect(repository.search())[0]
    result = BehaviorCorrelator().correlate(alert, repository.search())

    statements = Neo4jBehaviorGraphAdapter.build_statements(result.graph)

    assert statements
    assert any("MERGE (n:OpsGuardNode" in statement for statement, _ in statements)
    assert any("MERGE (a)-[r:RELATED" in statement for statement, _ in statements)

