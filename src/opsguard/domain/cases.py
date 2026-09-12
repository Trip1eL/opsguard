from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from opsguard.domain.models import Evidence


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    alert_id: str
    title: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.OPEN
    event_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    risk_score: float = Field(ge=0, le=1)


class CaseStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class Case(BaseModel):
    case_id: str
    title: str
    status: CaseStatus = CaseStatus.NEW
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
