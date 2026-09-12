"""Stateful local application service built on the deterministic core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from opsguard.agents import (
    InvestigationOrchestrator,
    InvestigationRequest,
    InvestigationToolbox,
)
from opsguard.attack import AttackTechniqueMapper, TechniqueCatalog
from opsguard.data import DatasetRecord, load_dataset, load_manifest
from opsguard.domain.models import DetectionRule
from opsguard.feedback import (
    FeedbackFlywheel,
    FeedbackKind,
    FeedbackRecord,
)
from opsguard.llm import (
    InvestigationPlanner,
    ModelPlanningError,
    ModelRuntimeStatus,
    PlanningResult,
)
from opsguard.repositories import JsonlEventRepository

INVESTIGATION_PARAMETER_ALLOWLIST = {
    "action",
    "domain",
    "dst_ip",
    "end_time",
    "event_ids",
    "host",
    "process",
    "requested_technique_ids",
    "rule_version",
    "source",
    "src_ip",
    "start_time",
    "user",
}


@dataclass
class StoredInvestigation:
    investigation_id: str
    question: str
    parameters: dict[str, Any]
    report: dict[str, Any]


class OpsGuardService:
    def __init__(
        self,
        project_root: Path,
        planner: InvestigationPlanner | None = None,
        model_status: ModelRuntimeStatus | None = None,
    ) -> None:
        self.project_root = project_root
        self.planner = planner
        self.model_runtime_status = model_status or ModelRuntimeStatus(
            enabled=False,
            configured=False,
        )
        manifest = load_manifest(project_root / "datasets" / "manifest.json")
        self.records: list[DatasetRecord] = [
            record
            for item in manifest.cases
            for record in load_dataset(project_root / "datasets" / item["file"])
        ]
        repository = JsonlEventRepository.from_dataset_records(self.records)
        catalog = TechniqueCatalog.from_json(
            project_root / "knowledge" / "attack" / "techniques.json"
        )
        toolbox = InvestigationToolbox(
            repository,
            AttackTechniqueMapper(catalog),
            validation_records=self.records,
        )
        self.orchestrator = InvestigationOrchestrator(toolbox.registry())
        self.flywheel = FeedbackFlywheel()
        self.investigations: dict[str, StoredInvestigation] = {}

    def investigate(
        self,
        question: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        parameters = parameters or {}
        unsupported = set(parameters) - INVESTIGATION_PARAMETER_ALLOWLIST
        if unsupported:
            raise ValueError(
                f"unsupported investigation parameters: {sorted(unsupported)}"
            )
        effective_parameters = dict(parameters)
        agent_plan: dict[str, Any] = {
            "mode": "deterministic",
            "policy": "fixed allow-listed workflow",
        }
        model_observability = self._empty_model_observability()
        if self.planner is not None:
            try:
                planning = self.planner.plan(question, dict(parameters))
            except Exception as exc:  # noqa: BLE001
                agent_plan = {
                    "mode": "deterministic_fallback",
                    "policy": "fixed allow-listed workflow",
                    "error": self._safe_model_error(exc),
                }
                model_observability["fallback_used"] = True
            else:
                planned_parameters = planning.plan.execution_parameters()
                unsupported_planned = (
                    set(planned_parameters) - INVESTIGATION_PARAMETER_ALLOWLIST
                )
                if unsupported_planned:
                    raise ModelPlanningError(
                        "validated model plan produced unsupported parameters"
                    )
                effective_parameters = {
                    **planned_parameters,
                    **parameters,
                }
                agent_plan = {
                    "mode": "llm",
                    "plan": planning.plan.model_dump(mode="json"),
                    "policy": (
                        "model proposes scope; deterministic allow-listed "
                        "workflow executes"
                    ),
                    "applied_parameters": planned_parameters,
                }
                model_observability = self._model_observability(planning)

        investigation_id = str(uuid4())
        report = self.orchestrator.run(
            InvestigationRequest(
                question=question,
                parameters=effective_parameters,
            )
        ).to_dict()
        report["agent_plan"] = agent_plan
        report["model_observability"] = model_observability
        stored = StoredInvestigation(
            investigation_id=investigation_id,
            question=question,
            parameters=effective_parameters,
            report=report,
        )
        self.investigations[investigation_id] = stored
        return self.serialize(stored)

    def decide(
        self,
        investigation_id: str,
        actor: str,
        approved: bool,
        reason: str,
        canary_metrics: dict[str, Any] | None,
    ) -> dict[str, Any]:
        stored = self.get(investigation_id)
        governance_status = self._governance_status(stored.report)
        if governance_status != "awaiting_approval":
            raise ValueError(
                "investigation is not awaiting approval: "
                f"{governance_status}"
            )
        scope_id = self._scope_id(stored.report)
        parameters = {
            **stored.parameters,
            "approval": {
                "approval_id": str(uuid4()),
                "scope_id": scope_id,
                "actor": actor,
                "approved": approved,
                "reason": reason,
                "created_at": datetime.now(UTC).isoformat(),
            },
        }
        if approved and canary_metrics is not None:
            parameters["canary_metrics"] = canary_metrics
        agent_plan = stored.report.get("agent_plan")
        model_observability = stored.report.get("model_observability")
        stored.report = self.orchestrator.run(
            InvestigationRequest(
                question=stored.question,
                parameters=parameters,
            )
        ).to_dict()
        if agent_plan is not None:
            stored.report["agent_plan"] = agent_plan
        if model_observability is not None:
            stored.report["model_observability"] = model_observability
        return self.serialize(stored)

    def add_feedback(
        self,
        investigation_id: str,
        event_id: str,
        kind: FeedbackKind,
        actor: str,
        comment: str,
    ) -> FeedbackRecord:
        stored = self.get(investigation_id)
        event_ids = {record.event.event_id for record in self.records}
        if event_id not in event_ids:
            raise ValueError(f"unknown feedback event: {event_id}")
        rule = self._rule(stored.report)
        feedback = FeedbackRecord(
            feedback_id=str(uuid4()),
            investigation_id=investigation_id,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            event_id=event_id,
            kind=kind,
            actor=actor,
            comment=comment,
            created_at=datetime.now(UTC),
        )
        self.flywheel.store.add(feedback)
        return feedback

    def evolve(self, investigation_id: str) -> dict[str, Any]:
        stored = self.get(investigation_id)
        rule = self._rule(stored.report)
        target_ids = set(
            stored.report["evidence"]["rule_validations"][0]["event_ids"]
        )
        proposal = self.flywheel.evolve(
            rule,
            self.records,
            target_event_ids=target_ids,
        )
        return proposal.model_dump(mode="json")

    def get(self, investigation_id: str) -> StoredInvestigation:
        try:
            return self.investigations[investigation_id]
        except KeyError as exc:
            raise KeyError(f"unknown investigation: {investigation_id}") from exc

    def list_feedback(self) -> list[dict[str, Any]]:
        return [
            record.model_dump(mode="json")
            for record in self.flywheel.store.list()
        ]

    def event_options(self) -> list[dict[str, Any]]:
        return [
            {
                "event_id": record.event.event_id,
                "label": record.event_label,
                "scenario": record.scenario,
                "action": record.event.action,
                "host": record.event.host,
            }
            for record in self.records
        ]

    def model_status(self) -> dict[str, Any]:
        return self.model_runtime_status.model_dump(mode="json")

    def _empty_model_observability(self) -> dict[str, Any]:
        return {
            **self.model_status(),
            "calls": [],
            "total_latency_ms": 0.0,
            "total_tokens": 0,
            "validation_attempts": 0,
            "validation_errors": [],
            "fallback_used": False,
        }

    def _model_observability(
        self,
        planning: PlanningResult,
    ) -> dict[str, Any]:
        calls = [call.model_dump(mode="json") for call in planning.calls]
        return {
            **self.model_status(),
            "calls": calls,
            "total_latency_ms": sum(call.latency_ms for call in planning.calls),
            "total_tokens": sum(
                call.total_tokens or 0 for call in planning.calls
            ),
            "validation_attempts": planning.validation_attempts,
            "validation_errors": planning.validation_errors,
            "fallback_used": False,
        }

    @staticmethod
    def _safe_model_error(exc: Exception) -> str:
        if isinstance(exc, ModelPlanningError):
            message = str(exc).replace("\n", " ").strip()
            return f"ModelPlanningError: {message[:300]}"
        return f"{type(exc).__name__}: external model planning failed"

    @staticmethod
    def _scope_id(report: dict[str, Any]) -> str:
        governance = report.get("evidence", {}).get("governance", [])
        if not governance:
            raise ValueError("investigation has no governable scope")
        return governance[0]["assessment"]["scope_id"]

    @staticmethod
    def _governance_status(report: dict[str, Any]) -> str:
        governance = report.get("evidence", {}).get("governance", [])
        if not governance:
            raise ValueError("investigation has no governance outcome")
        return str(governance[0]["status"])

    @staticmethod
    def _rule(report: dict[str, Any]) -> DetectionRule:
        validations = report.get("evidence", {}).get("rule_validations", [])
        if not validations:
            raise ValueError("investigation has no candidate rule")
        return DetectionRule.model_validate(validations[0]["rule"])

    @staticmethod
    def serialize(stored: StoredInvestigation) -> dict[str, Any]:
        return {
            "investigation_id": stored.investigation_id,
            "question": stored.question,
            "report": stored.report,
        }
