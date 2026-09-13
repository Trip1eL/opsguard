from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from opsguard.agents import (
    InvestigationRequest,
    LangGraphInvestigationOrchestrator,
)
from opsguard.correlation import Neo4jBehaviorGraphAdapter
from opsguard.correlation.engine import BehaviorCorrelator
from opsguard.data import load_dataset
from opsguard.domain.cases import Alert, AlertSeverity
from opsguard.domain.models import Event
from opsguard.repositories import EventQuery, OpenSearchEventRepository
from opsguard.rules import DockerRuleSandbox
from opsguard.web.service import OpsGuardService

ROOT = Path(__file__).parents[1]


def _events() -> list[Event]:
    return [
        record.event
        for record in load_dataset(
            ROOT / "datasets" / "suspicious" / "ssh_persistence.jsonl"
        )
    ]


class _FakeIndices:
    def __init__(self) -> None:
        self.created: dict[str, dict] = {}

    def exists(self, *, index: str) -> bool:
        return index in self.created

    def create(self, *, index: str, body: dict) -> None:
        self.created[index] = body


class _FakeOpenSearch:
    def __init__(self) -> None:
        self.indices = _FakeIndices()
        self.documents: dict[str, dict] = {}
        self.last_search: dict | None = None

    def bulk(self, *, body: list[dict], refresh: str) -> dict:
        assert refresh == "wait_for"
        for operation, document in zip(body[::2], body[1::2]):
            event_id = operation["index"]["_id"]
            self.documents[event_id] = document
        return {"errors": False}

    def index(self, *, index: str, id: str, body: dict, refresh: str) -> None:
        assert refresh == "wait_for"
        self.documents[id] = body

    def get(self, *, index: str, id: str) -> dict:
        return {"_source": self.documents[id]}

    def search(self, *, index: str, body: dict) -> dict:
        self.last_search = body
        return {
            "hits": {
                "hits": [
                    {"_source": document}
                    for document in self.documents.values()
                ]
            }
        }

    def count(self, *, index: str) -> dict:
        return {"count": len(self.documents)}


def test_opensearch_repository_indexes_and_builds_structured_queries() -> None:
    client = _FakeOpenSearch()
    repository = OpenSearchEventRepository(client)
    events = _events()

    repository.add_many(events)
    result = repository.search(EventQuery(host="web-03"))

    assert len(result) == 3
    assert repository.get("evt-ssh-001").event_id == "evt-ssh-001"
    assert len(repository) == 3
    assert client.last_search["query"]["bool"]["filter"] == [
        {"term": {"host": "web-03"}}
    ]
    assert client.indices.created["opsguard-events"]["mappings"]


def test_langgraph_orchestrator_executes_the_registered_workflow() -> None:
    service = OpsGuardService(ROOT)
    assert isinstance(service.orchestrator, LangGraphInvestigationOrchestrator)
    orchestrator = LangGraphInvestigationOrchestrator(service.orchestrator.registry)

    report = orchestrator.run(InvestigationRequest("调查新来源 SSH 登录后的可疑行为"))

    assert report.status.value == "awaiting_approval"
    assert [call.tool for call in report.tool_calls][-1] == "govern_policy_and_response"
    assert report.evidence["attack_mappings"]


def test_neo4j_adapter_supports_real_driver_factory_contract() -> None:
    with patch("neo4j.GraphDatabase.driver") as driver_factory:
        driver = Mock()
        driver_factory.return_value = driver
        adapter = Neo4jBehaviorGraphAdapter.from_uri(
            "bolt://localhost:7687",
            "neo4j",
            "test-password",
        )

    assert adapter.driver is driver
    driver_factory.assert_called_once_with(
        "bolt://localhost:7687",
        auth=("neo4j", "test-password"),
        encrypted=False,
    )


def test_neo4j_graph_store_is_used_by_behavior_correlation() -> None:
    graph_store = Mock()
    alert = Alert(
        alert_id="alert-suspicious_login-001",
        event_ids=["evt-ssh-001"],
        severity=AlertSeverity.HIGH,
        risk_score=0.9,
        title="test",
        evidence=[],
    )

    result = BehaviorCorrelator(graph_store=graph_store).correlate(alert, _events())

    graph_store.upsert.assert_called_once_with(result.graph)


def test_docker_sandbox_command_enforces_container_isolation() -> None:
    sandbox = DockerRuleSandbox(image="opsguard:test")
    with TemporaryDirectory() as temp:
        root = Path(temp)
        command = sandbox.command(root / "input.json", root / "output.json")

    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in command
    assert command[command.index("--memory") + 1] == "256m"
    assert command[command.index("--user") + 1] == "10001:10001"
    assert command[-3:] == [
        "opsguard.rules.docker_worker",
        "/run/opsguard/input.json",
        "/run/opsguard/work/output.json",
    ]
