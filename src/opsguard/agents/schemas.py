"""Structured contracts shared by investigation agents."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, date, datetime
from enum import Enum, StrEnum
from typing import Any

from pydantic import BaseModel


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


class InvestigationStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ToolErrorCategory(StrEnum):
    NOT_ALLOWED = "not_allowed"
    EMPTY_RESULT = "empty_result"
    INVALID_OUTPUT = "invalid_output"
    TIMEOUT = "timeout"
    EXECUTION = "execution"


@dataclass(frozen=True)
class InvestigationRequest:
    question: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    max_retries: int = 1

    def __post_init__(self) -> None:
        if not self.question.strip():
            raise ValueError("question must not be empty")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")


@dataclass
class ToolCallRecord:
    tool: str
    agent: str
    status: str
    attempt: int = 1
    input: Mapping[str, Any] = field(default_factory=dict)
    output: Any = None
    error: str | None = None
    error_category: ToolErrorCategory | None = None
    started_at: str = field(default_factory=_utc_now)
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))


@dataclass
class InvestigationReport:
    request: InvestigationRequest
    status: InvestigationStatus = InvestigationStatus.COMPLETED
    summary: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))
