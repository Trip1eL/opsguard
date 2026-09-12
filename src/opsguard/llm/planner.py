"""Validated LLM investigation planning with deterministic failure boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .config import ModelRuntimeConfig
from .gateway import JsonModelGateway, OpenAICompatibleGateway
from .models import (
    InvestigationPlan,
    ModelCallTrace,
    ModelRuntimeStatus,
    PlanningResult,
)

SYSTEM_PROMPT = """You are the planning component of OpsGuard.
Return exactly one JSON object matching the supplied schema.
You may propose investigation filters and an ordered sequence of registered tools.
Never include approval, response authorization, shell commands, code, SQL, credentials,
or fields outside the schema. Filters may contain only literal identifiers explicitly
present in the question. Do not infer hosts, users, IP addresses, time ranges, sources,
or actions from broad concepts such as SSH or web activity. Leave filters empty when
the question contains no exact identifier. Keep reasoning concise and evidence-neutral:
the deterministic tools, not the model, decide whether behavior is malicious."""


class ModelPlanningError(RuntimeError):
    """Raised after all structured-output validation attempts fail."""


class InvestigationPlanner:
    def __init__(
        self,
        gateway: JsonModelGateway,
        *,
        max_validation_attempts: int = 2,
    ) -> None:
        if max_validation_attempts < 1:
            raise ValueError("max_validation_attempts must be positive")
        self.gateway = gateway
        self.max_validation_attempts = max_validation_attempts

    def plan(
        self,
        question: str,
        explicit_parameters: dict[str, Any] | None = None,
    ) -> PlanningResult:
        prompt = self._prompt(question, explicit_parameters or {})
        calls: list[ModelCallTrace] = []
        validation_errors: list[str] = []
        for attempt in range(1, self.max_validation_attempts + 1):
            response = self.gateway.complete_json(
                SYSTEM_PROMPT,
                prompt,
                operation="investigation-plan",
            )
            calls.append(response.trace)
            try:
                plan = InvestigationPlan.model_validate(response.payload)
            except ValidationError as exc:
                errors = [
                    f"{'.'.join(str(part) for part in item['loc'])}: "
                    f"{item['msg']}"
                    for item in exc.errors(include_input=False)
                ]
                validation_errors.extend(errors)
                if attempt == self.max_validation_attempts:
                    break
                prompt = self._repair_prompt(
                    question,
                    explicit_parameters or {},
                    response.payload,
                    errors,
                )
                continue
            return PlanningResult(
                plan=plan,
                calls=calls,
                validation_attempts=attempt,
                validation_errors=validation_errors,
            )
        raise ModelPlanningError(
            "model plan failed schema validation after "
            f"{self.max_validation_attempts} attempt(s): "
            + "; ".join(validation_errors)
        )

    @staticmethod
    def _prompt(
        question: str,
        explicit_parameters: dict[str, Any],
    ) -> str:
        return json.dumps(
            {
                "question": question,
                "explicit_parameters": explicit_parameters,
                "schema": InvestigationPlan.model_json_schema(),
            },
            ensure_ascii=False,
        )

    @staticmethod
    def _repair_prompt(
        question: str,
        explicit_parameters: dict[str, Any],
        invalid_payload: dict[str, Any],
        errors: list[str],
    ) -> str:
        return json.dumps(
            {
                "instruction": "Repair the JSON object to satisfy the schema.",
                "question": question,
                "explicit_parameters": explicit_parameters,
                "invalid_payload": invalid_payload,
                "validation_errors": errors,
                "schema": InvestigationPlan.model_json_schema(),
            },
            ensure_ascii=False,
        )


def build_configured_planner(
    dotenv_path: Path,
) -> tuple[InvestigationPlanner | None, ModelRuntimeStatus]:
    config = ModelRuntimeConfig.from_env(dotenv_path)
    if not config.enabled:
        return None, ModelRuntimeStatus(
            enabled=False,
            configured=False,
            provider=config.provider,
            model=config.model,
            tracing_enabled=config.tracing_enabled,
            tracing_project=config.langsmith_project,
        )
    try:
        gateway = OpenAICompatibleGateway(config)
    except Exception as exc:  # noqa: BLE001
        return None, ModelRuntimeStatus(
            enabled=True,
            configured=False,
            provider=config.provider,
            model=config.model,
            tracing_enabled=config.tracing_enabled,
            tracing_project=config.langsmith_project,
            error=f"{type(exc).__name__}: model runtime initialization failed",
        )
    return InvestigationPlanner(gateway), ModelRuntimeStatus(
        enabled=True,
        configured=True,
        provider=config.provider,
        model=config.model,
        tracing_enabled=config.tracing_enabled,
        tracing_project=config.langsmith_project,
    )
