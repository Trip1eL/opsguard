"""Structured contracts for model planning and safe observability."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SAFE_FILTER_FIELDS = {
    "action",
    "domain",
    "dst_ip",
    "end_time",
    "event_ids",
    "host",
    "process",
    "source",
    "src_ip",
    "start_time",
    "user",
}


class PlannedTool(StrEnum):
    SEARCH_EVENTS = "search_events"
    DETECT_ANOMALIES = "detect_anomalies"
    CORRELATE_BEHAVIOR = "correlate_behavior"
    MAP_ATTACK_TECHNIQUES = "map_attack_techniques"
    GET_DETECTION_COVERAGE = "get_detection_coverage"
    GENERATE_DETECTION_RULES = "generate_detection_rules"
    VALIDATE_DETECTION_RULES = "validate_detection_rules"
    GOVERN_POLICY_AND_RESPONSE = "govern_policy_and_response"


TOOL_ORDER = {tool: index for index, tool in enumerate(PlannedTool)}


class InvestigationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=3, max_length=500)
    filters: dict[str, Any] = Field(default_factory=dict)
    focus_entities: list[str] = Field(default_factory=list, max_length=12)
    requested_technique_ids: list[str] = Field(
        default_factory=list,
        max_length=20,
    )
    tool_sequence: list[PlannedTool] = Field(
        default_factory=lambda: list(PlannedTool),
        min_length=1,
    )
    reasoning_summary: str = Field(min_length=3, max_length=1000)

    @field_validator("filters")
    @classmethod
    def validate_filters(cls, value: dict[str, Any]) -> dict[str, Any]:
        unsupported = set(value) - SAFE_FILTER_FIELDS
        if unsupported:
            raise ValueError(f"unsupported filters: {sorted(unsupported)}")
        for name, item in value.items():
            if isinstance(item, list):
                if not item or len(item) > 50:
                    raise ValueError(f"filter list has invalid size: {name}")
                if not all(isinstance(entry, str) for entry in item):
                    raise ValueError(f"filter list must contain strings: {name}")
            elif not isinstance(item, (str, int, float, bool)):
                raise ValueError(  # noqa: TRY004
                    f"unsupported filter value: {name}"
                )
        return value

    @field_validator("requested_technique_ids")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        for technique_id in value:
            head, separator, tail = technique_id.partition(".")
            if (
                not head.startswith("T")
                or not head[1:].isdigit()
                or (separator and not tail.isdigit())
            ):
                raise ValueError(f"invalid ATT&CK technique ID: {technique_id}")
        return list(dict.fromkeys(value))

    @field_validator("tool_sequence")
    @classmethod
    def validate_tool_order(
        cls,
        value: list[PlannedTool],
    ) -> list[PlannedTool]:
        if len(value) != len(set(value)):
            raise ValueError("tool_sequence must not contain duplicates")
        indexes = [TOOL_ORDER[item] for item in value]
        if indexes != sorted(indexes):
            raise ValueError("tool_sequence violates the safe dependency order")
        return value

    def execution_parameters(self) -> dict[str, Any]:
        parameters = dict(self.filters)
        if self.requested_technique_ids:
            parameters["requested_technique_ids"] = list(
                self.requested_technique_ids
            )
        return parameters


class ModelCallTrace(BaseModel):
    provider: str
    model: str
    trace_id: str | None = None
    trace_url: str | None = None
    latency_ms: float = Field(ge=0)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    finish_reason: str | None = None
    traced: bool = False


class GatewayResponse(BaseModel):
    payload: dict[str, Any]
    trace: ModelCallTrace


class PlanningResult(BaseModel):
    plan: InvestigationPlan
    calls: list[ModelCallTrace]
    validation_attempts: int = Field(ge=1)
    validation_errors: list[str] = Field(default_factory=list)


class ModelRuntimeStatus(BaseModel):
    enabled: bool
    configured: bool
    provider: str = ""
    model: str = ""
    tracing_enabled: bool = False
    tracing_project: str = ""
    error: str | None = None
