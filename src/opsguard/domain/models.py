from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EventSource(StrEnum):
    LINUX_AUDIT = "linux_audit"
    WEB_ACCESS = "web_access"
    PROCESS_NETWORK = "process_network"


class Event(BaseModel):
    event_id: str
    timestamp: datetime
    source: EventSource
    host: str | None = None
    user: str | None = None
    action: str
    process: str | None = None
    parent_process: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    domain: str | None = None
    file: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_log: str | None = None


class Evidence(BaseModel):
    event_ids: list[str] = Field(default_factory=list)
    summary: str
    confidence: float = Field(ge=0, le=1)


class TechniqueMapping(BaseModel):
    technique_id: str
    name: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


class BehaviorChain(BaseModel):
    case_id: str
    event_ids: list[str] = Field(default_factory=list)
    stages: list[str] = Field(default_factory=list)
    risk_score: float = Field(ge=0, le=1)
    mappings: list[TechniqueMapping] = Field(default_factory=list)


class RuleStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    CANARY = "canary"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"


class DetectionRule(BaseModel):
    rule_id: str
    version: int = Field(ge=1)
    name: str
    format: str = "sigma"
    content: str
    status: RuleStatus = RuleStatus.DRAFT
    technique_ids: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    rule_id: str
    dataset: str
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    passed: bool


class Approval(BaseModel):
    actor: str
    approved: bool
    reason: str
    created_at: datetime
