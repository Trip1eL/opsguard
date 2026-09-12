"""Structured feedback and rule-evolution contracts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from opsguard.domain.models import DetectionRule
from opsguard.rules import RuleValidationReport


class FeedbackKind(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class FeedbackRecord(BaseModel):
    feedback_id: str
    investigation_id: str
    rule_id: str
    rule_version: int = Field(ge=1)
    event_id: str
    kind: FeedbackKind
    actor: str = Field(min_length=1)
    comment: str = Field(min_length=1)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("feedback timestamp must include a timezone")
        return value


class RuleEvolutionProposal(BaseModel):
    base_rule: DetectionRule
    candidate_rule: DetectionRule
    baseline_validation: RuleValidationReport
    candidate_validation: RuleValidationReport
    feedback_ids: list[str] = Field(default_factory=list)
    metric_deltas: dict[str, float] = Field(default_factory=dict)
    recommended: bool
    rationale: list[str] = Field(default_factory=list)
