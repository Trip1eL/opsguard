import json
from pathlib import Path

from opsguard.agents import (
    AgentStep,
    InvestigationOrchestrator,
    InvestigationRequest,
    InvestigationStatus,
    InvestigationToolbox,
    ToolErrorCategory,
    ToolRegistry,
    ToolSpec,
)
from opsguard.attack import AttackTechniqueMapper, TechniqueCatalog
from opsguard.data import load_dataset, load_manifest
from opsguard.repositories import JsonlEventRepository

ROOT = Path(__file__).parents[1]


def _mock_registry() -> ToolRegistry:
    return ToolRegistry(
        [
            ToolSpec(
                "search_events",
                "search normalized events",
                lambda _: [{"event_id": "e1"}],
            ),
            ToolSpec(
                "detect_anomalies",
                "run deterministic detectors",
                lambda _: [{"alert_id": "a1"}],
            ),
            ToolSpec(
                "correlate_behavior",
                "build behavior chain",
                lambda _: [{"chain": {"event_ids": ["e1"]}}],
            ),
            ToolSpec(
                "map_attack_techniques",
                "map evidence to ATT&CK",
                lambda _: [
                    {
                        "chain": {
                            "mappings": [{"technique_id": "T1059.004"}],
                        }
                    }
                ],
            ),
            ToolSpec(
                "get_detection_coverage",
                "calculate coverage",
                lambda _: [{"coverage_ratio": 1.0}],
            ),
            ToolSpec(
                "generate_detection_rules",
                "generate Sigma candidates",
                lambda _: [{"rule": {"rule_id": "r1"}}],
            ),
            ToolSpec(
                "validate_detection_rules",
                "validate Sigma candidates",
                lambda _: [{"result": {"passed": True}}],
            ),
        ]
    )


def _fixture_orchestrator() -> InvestigationOrchestrator:
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    repository = JsonlEventRepository(
        [ROOT / "datasets" / item["file"] for item in manifest.cases]
    )
    records = [
        record
        for item in manifest.cases
        for record in load_dataset(ROOT / "datasets" / item["file"])
    ]
    catalog = TechniqueCatalog.from_json(
        ROOT / "knowledge" / "attack" / "techniques.json"
    )
    toolbox = InvestigationToolbox(
        repository,
        AttackTechniqueMapper(catalog),
        validation_records=records,
    )
    return InvestigationOrchestrator(toolbox.registry())


def test_workflow_produces_auditable_evidence_chain() -> None:
    report = InvestigationOrchestrator(_mock_registry()).run(
        InvestigationRequest("investigate suspicious SSH activity")
    )

    assert report.status == InvestigationStatus.COMPLETED
    assert report.evidence["events"][0]["event_id"] == "e1"
    assert report.evidence["coverage"][0]["coverage_ratio"] == 1.0
    assert len(report.tool_calls) == 7
    assert all(call.status == "completed" for call in report.tool_calls)
    assert "1 ATT&CK technique(s)" in report.summary
    assert "1 candidate rule(s), 1 validated" in report.summary


def test_unknown_tool_stops_without_retrying() -> None:
    report = InvestigationOrchestrator(ToolRegistry()).run(
        InvestigationRequest("anything", max_retries=1)
    )

    assert report.status == InvestigationStatus.FAILED
    assert len(report.tool_calls) == 1
    assert all(call.status == "failed" for call in report.tool_calls)
    assert report.tool_calls[-1].error_category == ToolErrorCategory.NOT_ALLOWED
    assert "not in the allowlist" in report.tool_calls[-1].error


def test_transient_failure_is_retried_and_recovers() -> None:
    attempts = 0

    def flaky(_payload):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("temporary timeout")
        return [{"event_id": "e1"}]

    orchestrator = InvestigationOrchestrator(
        ToolRegistry([ToolSpec("search_events", "search", flaky)]),
        steps=(AgentStep("investigation", "search_events", output_key="events"),),
    )
    report = orchestrator.run(InvestigationRequest("retry", max_retries=1))

    assert report.status == InvestigationStatus.COMPLETED
    assert attempts == 2
    assert report.tool_calls[0].error_category == ToolErrorCategory.TIMEOUT
    assert report.tool_calls[1].status == "completed"


def test_structured_output_errors_are_classified() -> None:
    def require_list(value):
        if not isinstance(value, list):
            raise TypeError("list required")
        return value

    registry = ToolRegistry(
        [ToolSpec("search_events", "search", lambda _: {}, require_list)]
    )
    orchestrator = InvestigationOrchestrator(
        registry,
        steps=(AgentStep("investigation", "search_events", output_key="events"),),
    )
    report = orchestrator.run(InvestigationRequest("validate", max_retries=0))

    assert report.status == InvestigationStatus.FAILED
    assert report.tool_calls[0].error_category == ToolErrorCategory.INVALID_OUTPUT


def test_fixture_workflow_answers_ssh_question_end_to_end() -> None:
    report = _fixture_orchestrator().run(
        InvestigationRequest(
            "调查新来源 SSH 登录后的可疑行为",
            parameters={
                "requested_technique_ids": [
                    "T1021.004",
                    "T1053.003",
                    "T1105",
                ]
            },
        )
    )

    assert report.status == InvestigationStatus.COMPLETED
    assert len(report.evidence["alerts"]) == 1
    chain = report.evidence["attack_mappings"][0]["chain"]
    technique_ids = {item["technique_id"] for item in chain["mappings"]}
    assert {"T1021.004", "T1053.003", "T1105"} <= technique_ids
    assert report.evidence["coverage"][0]["coverage_ratio"] == 1.0
    assert report.evidence["rule_validations"][0]["result"]["passed"] is True
    assert report.evidence["rule_validations"][0]["rule"]["status"] == "validated"
    assert all(call.status == "completed" for call in report.tool_calls)
    json.dumps(report.to_dict(), ensure_ascii=False)


def test_empty_event_query_is_reported_without_downstream_calls() -> None:
    report = _fixture_orchestrator().run(
        InvestigationRequest(
            "调查不存在的主机",
            parameters={"host": "missing-host"},
            max_retries=0,
        )
    )

    assert report.status == InvestigationStatus.FAILED
    assert len(report.tool_calls) == 1
    assert report.tool_calls[0].error_category == ToolErrorCategory.EMPTY_RESULT
