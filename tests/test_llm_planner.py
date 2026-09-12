from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from opsguard.llm import (
    GatewayResponse,
    InvestigationPlan,
    InvestigationPlanner,
    ModelCallTrace,
    ModelRuntimeConfig,
    ModelRuntimeStatus,
    build_configured_planner,
)
from opsguard.web.service import OpsGuardService

ROOT = Path(__file__).parents[1]


def _payload(**updates: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "objective": "Investigate suspicious SSH behavior",
        "filters": {},
        "focus_entities": ["SSH session", "affected host"],
        "requested_technique_ids": ["T1021.004"],
        "tool_sequence": [
            "search_events",
            "detect_anomalies",
            "correlate_behavior",
            "map_attack_techniques",
        ],
        "reasoning_summary": (
            "Retrieve broad evidence before correlating and mapping behavior."
        ),
    }
    payload.update(updates)
    return payload


def _trace(index: int = 1) -> ModelCallTrace:
    return ModelCallTrace(
        provider="fake",
        model="test-model",
        trace_id=f"trace-{index}",
        trace_url=f"https://trace.invalid/{index}",
        latency_ms=10,
        prompt_tokens=20,
        completion_tokens=10,
        total_tokens=30,
        finish_reason="stop",
        traced=True,
    )


class FakeGateway:
    def __init__(self, responses: list[dict[str, Any] | Exception]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def complete_json(
        self,
        _system_prompt: str,
        _user_prompt: str,
        *,
        operation: str,
    ) -> GatewayResponse:
        assert operation == "investigation-plan"
        response = self.responses[self.calls]
        self.calls += 1
        if isinstance(response, Exception):
            raise response
        return GatewayResponse(payload=response, trace=_trace(self.calls))


def test_model_config_keeps_secrets_out_of_repr(tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        """OPSGUARD_LLM_ENABLED=true
CHAT_MODEL_PROVIDER=relay
GPT_MODEL_NAME=test-model
RELAY_API_KEY=super-secret-key
RELAY_BASE_URL=https://relay.example.com
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=langsmith-secret
LANGSMITH_PROJECT=opsguard-test
""",
        encoding="utf-8",
    )

    config = ModelRuntimeConfig.from_env(dotenv)

    assert config.openai_base_url == "https://relay.example.com/v1"
    assert config.langsmith_project == "opsguard-test"
    assert "super-secret-key" not in repr(config)
    assert "langsmith-secret" not in repr(config)
    config.validate()


def test_invalid_runtime_status_does_not_expose_secret(
    tmp_path: Path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        """OPSGUARD_LLM_ENABLED=true
CHAT_MODEL_PROVIDER=relay
GPT_MODEL_NAME=test-model
RELAY_API_KEY=super-secret-key
RELAY_BASE_URL=not-a-url
""",
        encoding="utf-8",
    )

    planner, status = build_configured_planner(dotenv)

    assert planner is None
    assert status.configured is False
    assert status.error == "ValueError: model runtime initialization failed"
    assert "super-secret-key" not in status.model_dump_json()


def test_plan_rejects_approval_and_out_of_order_tools() -> None:
    with pytest.raises(ValidationError, match="unsupported filters"):
        InvestigationPlan.model_validate(
            _payload(filters={"approval": {"approved": True}})
        )

    with pytest.raises(ValidationError, match="safe dependency order"):
        InvestigationPlan.model_validate(
            _payload(
                tool_sequence=[
                    "detect_anomalies",
                    "search_events",
                ]
            )
        )


def test_planner_repairs_invalid_structured_output() -> None:
    gateway = FakeGateway(
        [
            _payload(filters={"approval": True}),
            _payload(filters={"host": "web-03"}),
        ]
    )

    result = InvestigationPlanner(gateway).plan("调查 web-03")

    assert result.plan.filters == {"host": "web-03"}
    assert result.validation_attempts == 2
    assert len(result.validation_errors) == 1
    assert [call.trace_id for call in result.calls] == ["trace-1", "trace-2"]


def test_service_uses_validated_plan_and_preserves_trace_on_decision() -> None:
    planner = InvestigationPlanner(FakeGateway([_payload()]))
    status = ModelRuntimeStatus(
        enabled=True,
        configured=True,
        provider="fake",
        model="test-model",
        tracing_enabled=True,
        tracing_project="opsguard-test",
    )
    service = OpsGuardService(ROOT, planner, status)

    investigation = service.investigate(
        "调查新来源 SSH 登录后的可疑行为",
        {"rule_version": 3},
    )

    report = investigation["report"]
    assert report["agent_plan"]["mode"] == "llm"
    assert report["agent_plan"]["applied_parameters"] == {
        "requested_technique_ids": ["T1021.004"]
    }
    assert report["evidence"]["rule_validations"][0]["rule"]["version"] == 3
    assert report["model_observability"]["total_tokens"] == 30
    assert report["model_observability"]["calls"][0]["trace_id"] == "trace-1"

    decided = service.decide(
        investigation["investigation_id"],
        "soc-lead",
        False,
        "证据复核后拒绝处置",
        None,
    )

    assert decided["report"]["agent_plan"] == report["agent_plan"]
    assert (
        decided["report"]["model_observability"]
        == report["model_observability"]
    )


def test_service_falls_back_without_exposing_external_error_details() -> None:
    planner = InvestigationPlanner(
        FakeGateway([TimeoutError("secret-bearing upstream message")])
    )
    status = ModelRuntimeStatus(
        enabled=True,
        configured=True,
        provider="fake",
        model="test-model",
    )
    service = OpsGuardService(ROOT, planner, status)

    investigation = service.investigate("调查 SSH 异常行为")

    plan = investigation["report"]["agent_plan"]
    assert plan["mode"] == "deterministic_fallback"
    assert plan["error"] == "TimeoutError: external model planning failed"
    assert "secret-bearing" not in str(investigation)
    assert investigation["report"]["status"] == "awaiting_approval"
