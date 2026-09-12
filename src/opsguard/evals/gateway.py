"""Deterministic model gateway used by the free fixture evaluation mode."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from opsguard.llm import GatewayResponse, ModelCallTrace

from .models import EvalCase, FixtureAction

SAFE_TOOL_SEQUENCE = [
    "search_events",
    "detect_anomalies",
    "correlate_behavior",
    "map_attack_techniques",
    "get_detection_coverage",
    "generate_detection_rules",
    "validate_detection_rules",
    "govern_policy_and_response",
]


class ScriptedEvalGateway:
    """Replay an explicit response script without network or credentials."""

    def __init__(self, case: EvalCase) -> None:
        self.case = case
        self.calls = 0

    def complete_json(
        self,
        _system_prompt: str,
        _user_prompt: str,
        *,
        operation: str,
    ) -> GatewayResponse:
        if operation != "investigation-plan":
            raise ValueError(f"unsupported fixture operation: {operation}")
        action = self.case.fixture_script[self.calls]
        self.calls += 1
        if action == FixtureAction.TIMEOUT:
            raise TimeoutError("fixture model timeout")
        if action == FixtureAction.INVALID_JSON:
            raise json.JSONDecodeError("fixture invalid JSON", "{", 1)

        payload = self._valid_payload()
        if action == FixtureAction.UNSAFE_SCHEMA:
            payload["approval"] = {
                "approved": True,
                "action": "isolate_host",
            }
        return GatewayResponse(payload=payload, trace=self._trace())

    def _valid_payload(self) -> dict[str, Any]:
        return {
            "objective": f"Evaluate investigation case {self.case.case_id}",
            "filters": deepcopy(self.case.valid_plan_filters),
            "focus_entities": [],
            "requested_technique_ids": [],
            "tool_sequence": list(SAFE_TOOL_SEQUENCE),
            "reasoning_summary": (
                "Use the fixed evidence workflow and preserve governance controls."
            ),
        }

    def _trace(self) -> ModelCallTrace:
        index = self.calls
        return ModelCallTrace(
            provider="fixture",
            model="scripted-eval-model",
            trace_id=f"fixture-{self.case.case_id}-{index}",
            latency_ms=5.0,
            prompt_tokens=20,
            completion_tokens=10,
            total_tokens=30,
            finish_reason="stop",
            traced=False,
        )
