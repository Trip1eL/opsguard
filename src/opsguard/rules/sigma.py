"""Generate and safely evaluate the constrained Sigma subset used by OpsGuard."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import yaml
from pydantic import BaseModel, Field

from opsguard.domain.models import BehaviorChain, DetectionRule, Event

SUPPORTED_FIELDS = {
    "action",
    "domain",
    "dst_ip",
    "file",
    "host",
    "parent_process",
    "process",
    "source",
    "src_ip",
    "user",
}
SUPPORTED_MODIFIERS = {"contains", "endswith", "startswith"}

TECHNIQUE_SELECTIONS: dict[str, dict[str, Any]] = {
    "T1021.004": {
        "action": "ssh_login",
        "attributes.auth_method": "password",
        "attributes.new_source": True,
    },
    "T1053.003": {
        "action": "scheduled_task_create",
        "attributes.command|contains": ["/tmp/", "/var/tmp/"],
    },
    "T1059.004": {
        "action": "process_start",
        "process": ["bash", "sh", "zsh", "powershell", "cmd", "python", "python3"],
    },
    "T1105": {
        "action": "process_start",
        "process": ["curl", "wget"],
    },
    "T1505.003": {
        "action": "process_start",
        "parent_process": ["nginx", "apache2", "httpd", "gunicorn"],
        "process": ["bash", "sh", "zsh", "powershell", "cmd", "python", "python3"],
    },
    "T1071.001": {
        "action": "network_connect",
        "attributes.dst_port": [80, 443],
    },
}


class SigmaValidationError(ValueError):
    """Raised when a candidate uses invalid or unsupported Sigma constructs."""


class SigmaDocument(BaseModel):
    title: str
    rule_id: str
    logsource: dict[str, Any]
    selections: dict[str, dict[str, Any]]
    condition: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SigmaRuleGenerator:
    """Create deterministic, versioned Sigma candidates from mapped behavior."""

    def generate(self, chain: BehaviorChain, version: int = 1) -> DetectionRule:
        technique_ids = sorted(
            {
                mapping.technique_id
                for mapping in chain.mappings
                if mapping.technique_id in TECHNIQUE_SELECTIONS
            }
        )
        if not technique_ids:
            raise ValueError("behavior chain has no supported ATT&CK mappings")
        if version < 1:
            raise ValueError("rule version must be at least 1")

        signature = ",".join(technique_ids)
        rule_id = str(uuid5(NAMESPACE_URL, f"opsguard:sigma:{signature}"))
        selections = {
            f"selection_{technique_id.lower().replace('.', '_')}": deepcopy(
                TECHNIQUE_SELECTIONS[technique_id]
            )
            for technique_id in technique_ids
        }
        document = {
            "title": f"OpsGuard behavior detection for {', '.join(technique_ids)}",
            "id": rule_id,
            "status": "experimental",
            "description": (
                "Candidate generated from an evidence-backed OpsGuard behavior chain."
            ),
            "author": "OpsGuard",
            "logsource": {"category": "application", "product": "opsguard"},
            "detection": {**selections, "condition": "1 of selection_*"},
            "falsepositives": ["Authorized administrative activity"],
            "level": "high" if chain.risk_score >= 0.85 else "medium",
            "tags": [
                f"attack.{technique_id.lower()}" for technique_id in technique_ids
            ],
            "x_opsguard": {
                "case_id": chain.case_id,
                "event_ids": chain.event_ids,
                "version": version,
            },
        }
        return DetectionRule(
            rule_id=rule_id,
            version=version,
            name=document["title"],
            content=yaml.safe_dump(
                document,
                allow_unicode=False,
                sort_keys=False,
            ),
            technique_ids=technique_ids,
        )


class SigmaRuleValidator:
    """Parse Sigma with safe YAML and enforce the executable field allowlist."""

    def parse(self, rule: DetectionRule) -> SigmaDocument:
        if rule.format.casefold() != "sigma":
            raise SigmaValidationError(f"unsupported rule format: {rule.format}")
        if len(rule.content.encode("utf-8")) > 65_536:
            raise SigmaValidationError("Sigma document exceeds the 64 KiB limit")
        try:
            document = yaml.safe_load(rule.content)
        except yaml.YAMLError as exc:
            raise SigmaValidationError(f"invalid Sigma YAML: {exc}") from exc
        if not isinstance(document, dict):
            raise SigmaValidationError("Sigma document must be an object")

        for field in ("title", "id", "logsource", "detection"):
            if field not in document:
                raise SigmaValidationError(f"missing required Sigma field: {field}")
        if not isinstance(document["title"], str):
            raise SigmaValidationError("Sigma title must be a string")
        if not isinstance(document["logsource"], dict):
            raise SigmaValidationError("Sigma logsource must be an object")
        if document["id"] != rule.rule_id:
            raise SigmaValidationError("Sigma id does not match DetectionRule.rule_id")

        detection = document["detection"]
        if not isinstance(detection, dict):
            raise SigmaValidationError("detection must be an object")
        condition = detection.get("condition")
        if condition != "1 of selection_*":
            raise SigmaValidationError(
                "only the condition '1 of selection_*' is supported"
            )
        selections = {
            name: value
            for name, value in detection.items()
            if name != "condition"
        }
        if not selections:
            raise SigmaValidationError("at least one selection is required")
        for name, selection in selections.items():
            if not name.startswith("selection_") or not isinstance(selection, dict):
                raise SigmaValidationError(f"invalid selection: {name}")
            if not selection:
                raise SigmaValidationError(f"selection must not be empty: {name}")
            for expression, expected in selection.items():
                self._validate_expression(expression, expected)

        return SigmaDocument(
            title=str(document["title"]),
            rule_id=str(document["id"]),
            logsource=document["logsource"],
            selections=selections,
            condition=condition,
            tags=document.get("tags", []),
            metadata=document.get("x_opsguard", {}),
        )

    @staticmethod
    def _validate_expression(expression: str, expected: Any) -> None:
        field, separator, modifier = expression.partition("|")
        valid_field = field in SUPPORTED_FIELDS or (
            field.startswith("attributes.") and len(field.split(".", maxsplit=1)[1]) > 0
        )
        if not valid_field:
            raise SigmaValidationError(f"field is not allow-listed: {field}")
        if separator and modifier not in SUPPORTED_MODIFIERS:
            raise SigmaValidationError(f"modifier is not supported: {modifier}")
        values = expected if isinstance(expected, list) else [expected]
        if not values or any(
            not isinstance(value, (str, int, float, bool)) for value in values
        ):
            raise SigmaValidationError(
                f"unsupported comparison value for expression: {expression}"
            )


@dataclass(frozen=True)
class CompiledSigmaRule:
    document: SigmaDocument

    def matches(self, event: Event) -> bool:
        return any(
            all(_matches_expression(event, expression, expected) for expression, expected in selection.items())
            for selection in self.document.selections.values()
        )


class SigmaRuleMatcher:
    def __init__(self, validator: SigmaRuleValidator | None = None) -> None:
        self.validator = validator or SigmaRuleValidator()

    def compile(self, rule: DetectionRule) -> CompiledSigmaRule:
        return CompiledSigmaRule(self.validator.parse(rule))


def _matches_expression(event: Event, expression: str, expected: Any) -> bool:
    field, _, modifier = expression.partition("|")
    actual = _field_value(event, field)
    candidates = expected if isinstance(expected, list) else [expected]
    if modifier == "contains":
        return actual is not None and any(
            str(candidate) in str(actual) for candidate in candidates
        )
    if modifier == "startswith":
        return actual is not None and any(
            str(actual).startswith(str(candidate)) for candidate in candidates
        )
    if modifier == "endswith":
        return actual is not None and any(
            str(actual).endswith(str(candidate)) for candidate in candidates
        )
    return actual in candidates


def _field_value(event: Event, field: str) -> Any:
    if field.startswith("attributes."):
        return event.attributes.get(field.split(".", maxsplit=1)[1])
    value = getattr(event, field)
    return value.value if hasattr(value, "value") else value
