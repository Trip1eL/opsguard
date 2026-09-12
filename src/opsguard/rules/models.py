"""Validation contracts for candidate detection rules."""

from __future__ import annotations

from pydantic import BaseModel, Field

from opsguard.domain.models import DetectionRule, ValidationResult


class ValidationThresholds(BaseModel):
    min_precision: float = Field(default=0.90, ge=0, le=1)
    min_recall: float = Field(default=0.80, ge=0, le=1)
    max_false_positive_rate: float = Field(default=0.05, ge=0, le=1)
    max_latency_ms: float = Field(default=100.0, gt=0)


class ValidationSample(BaseModel):
    event_id: str
    case_id: str
    scenario: str
    expected_label: str
    matched: bool


class RuleValidationReport(BaseModel):
    rule: DetectionRule
    result: ValidationResult
    true_negative: int = Field(ge=0)
    false_positive_rate: float = Field(ge=0, le=1)
    execution_latency_ms: float = Field(ge=0)
    evaluated_event_ids: list[str] = Field(default_factory=list)
    matched_event_ids: list[str] = Field(default_factory=list)
    false_positive_samples: list[ValidationSample] = Field(default_factory=list)
    false_negative_samples: list[ValidationSample] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
