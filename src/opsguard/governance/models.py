"""Typed governance, approval, response, canary, and audit contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from opsguard.domain.models import DetectionRule


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GovernanceStatus(StrEnum):
    VALIDATION_FAILED = "validation_failed"
    AWAITING_APPROVAL = "awaiting_approval"
    DENIED = "denied"
    CANARY = "canary"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"


class ResponseActionType(StrEnum):
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    BLOCK_DOMAIN = "block_domain"


class AuditAction(StrEnum):
    RISK_ASSESSED = "risk_assessed"
    RESPONSE_PROPOSED = "response_proposed"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_RECORDED = "approval_recorded"
    RESPONSE_EXECUTED = "response_executed"
    RESPONSE_BLOCKED = "response_blocked"
    RULE_TRANSITIONED = "rule_transitioned"
    RULE_TRANSITION_REJECTED = "rule_transition_rejected"
    CANARY_EVALUATED = "canary_evaluated"


class RiskAssessment(BaseModel):
    scope_id: str
    score: float = Field(ge=0, le=1)
    level: RiskLevel
    requires_human_approval: bool
    factors: list[str] = Field(default_factory=list)


class ResponseAction(BaseModel):
    action_type: ResponseActionType
    target: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class ResponseProposal(BaseModel):
    proposal_id: str
    scope_id: str
    risk: RiskAssessment
    actions: list[ResponseAction] = Field(default_factory=list)
    requires_approval: bool = True


class ApprovalDecision(BaseModel):
    approval_id: str
    scope_id: str
    actor: str = Field(min_length=1)
    approved: bool
    reason: str = Field(min_length=1)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamp must include a timezone")
        return value


class ResponseExecution(BaseModel):
    action: ResponseAction
    status: str
    result: str


class CanaryMetrics(BaseModel):
    evaluated_events: int = Field(ge=1)
    false_positive_rate: float = Field(ge=0, le=1)
    error_rate: float = Field(ge=0, le=1)
    p95_latency_ms: float = Field(ge=0)


class CanaryPolicy(BaseModel):
    min_evaluated_events: int = Field(default=1, ge=1)
    max_false_positive_rate: float = Field(default=0.05, ge=0, le=1)
    max_error_rate: float = Field(default=0.01, ge=0, le=1)
    max_p95_latency_ms: float = Field(default=200.0, gt=0)


class AuditRecord(BaseModel):
    audit_id: str
    scope_id: str
    action: AuditAction
    actor: str
    reason: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resource_id: str | None = None
    before: str | None = None
    after: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GovernanceOutcome(BaseModel):
    status: GovernanceStatus
    assessment: RiskAssessment
    proposal: ResponseProposal
    rule: DetectionRule
    approval: ApprovalDecision | None = None
    canary_metrics: CanaryMetrics | None = None
    response_executions: list[ResponseExecution] = Field(default_factory=list)
    audit_records: list[AuditRecord] = Field(default_factory=list)
