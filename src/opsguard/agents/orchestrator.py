"""Explicit, inspectable multi-agent investigation state machine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .schemas import (
    InvestigationReport,
    InvestigationRequest,
    InvestigationStatus,
    ToolCallRecord,
    ToolErrorCategory,
)
from .tools import (
    EmptyToolResultError,
    InvalidToolOutputError,
    ToolNotAllowedError,
    ToolRegistry,
)


@dataclass(frozen=True)
class AgentStep:
    agent: str
    tool: str
    input_keys: tuple[str, ...] = ()
    output_key: str = "result"


DEFAULT_STEPS: tuple[AgentStep, ...] = (
    AgentStep("investigation", "search_events", output_key="events"),
    AgentStep(
        "detection",
        "detect_anomalies",
        input_keys=("events",),
        output_key="alerts",
    ),
    AgentStep(
        "correlation",
        "correlate_behavior",
        input_keys=("events", "alerts"),
        output_key="behavior_chains",
    ),
    AgentStep(
        "attack_mapping",
        "map_attack_techniques",
        input_keys=("events", "behavior_chains"),
        output_key="attack_mappings",
    ),
    AgentStep(
        "evaluation",
        "get_detection_coverage",
        input_keys=("attack_mappings",),
        output_key="coverage",
    ),
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class InvestigationOrchestrator:
    """Run a bounded workflow with auditable tool calls and failure retries."""

    def __init__(
        self,
        registry: ToolRegistry,
        steps: tuple[AgentStep, ...] = DEFAULT_STEPS,
    ) -> None:
        self.registry = registry
        self.steps = steps

    def run(self, request: InvestigationRequest) -> InvestigationReport:
        report = InvestigationReport(request=request)
        state: dict[str, Any] = dict(request.parameters)

        for step in self.steps:
            payload = {**request.parameters, "question": request.question}
            payload.update({key: state[key] for key in step.input_keys if key in state})
            ok, value = self._invoke_with_retry(
                report,
                step,
                payload,
                request.max_retries,
            )
            if not ok:
                report.status = (
                    InvestigationStatus.PARTIAL
                    if report.evidence
                    else InvestigationStatus.FAILED
                )
                break
            state[step.output_key] = value
            report.evidence[step.output_key] = value

        report.summary = self._summarize(report)
        return report

    def _invoke_with_retry(
        self,
        report: InvestigationReport,
        step: AgentStep,
        payload: Mapping[str, Any],
        max_retries: int,
    ) -> tuple[bool, Any]:
        total_attempts = max_retries + 1
        last_error: str | None = None
        attempts_made = 0
        for attempt in range(1, total_attempts + 1):
            attempts_made = attempt
            call = ToolCallRecord(
                tool=step.tool,
                agent=step.agent,
                status="running",
                attempt=attempt,
                input=payload,
            )
            try:
                value = self.registry.invoke(step.tool, payload)
            # Tool implementations are plug-ins; every failure must become trace data.
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"
                call.status = "failed"
                call.error = last_error
                call.error_category = self._error_category(exc)
                call.finished_at = _now()
                report.tool_calls.append(call)
                if call.error_category not in {
                    ToolErrorCategory.TIMEOUT,
                    ToolErrorCategory.EXECUTION,
                }:
                    break
                continue
            call.status = "completed"
            call.output = value
            call.finished_at = _now()
            report.tool_calls.append(call)
            return True, value

        report.failures.append(
            f"{step.tool} failed after {attempts_made} attempt(s): {last_error}"
        )
        return False, None

    @staticmethod
    def _error_category(exc: Exception) -> ToolErrorCategory:
        if isinstance(exc, ToolNotAllowedError):
            return ToolErrorCategory.NOT_ALLOWED
        if isinstance(exc, EmptyToolResultError):
            return ToolErrorCategory.EMPTY_RESULT
        if isinstance(exc, InvalidToolOutputError):
            return ToolErrorCategory.INVALID_OUTPUT
        if isinstance(exc, TimeoutError):
            return ToolErrorCategory.TIMEOUT
        return ToolErrorCategory.EXECUTION

    @staticmethod
    def _summarize(report: InvestigationReport) -> str:
        evidence = report.evidence
        events = len(evidence.get("events", []))
        alerts = len(evidence.get("alerts", []))
        chains = len(evidence.get("behavior_chains", []))
        techniques = {
            mapping["technique_id"]
            for item in evidence.get("attack_mappings", [])
            for mapping in item.get("chain", {}).get("mappings", [])
        }
        return (
            f"Investigation {report.status.value}: {events} event(s), "
            f"{alerts} alert(s), {chains} behavior chain(s), "
            f"{len(techniques)} ATT&CK technique(s)."
        )
