from __future__ import annotations

from enum import StrEnum


class WorkflowState(StrEnum):
    RECEIVED = "received"
    NORMALIZED = "normalized"
    INVESTIGATING = "investigating"
    CORRELATED = "correlated"
    MAPPED = "mapped"
    RULE_GENERATED = "rule_generated"
    VALIDATING = "validating"
    AWAITING_APPROVAL = "awaiting_approval"
    PUBLISHED = "published"
    MONITORING = "monitoring"
    COMPLETED = "completed"
    FAILED = "failed"


ALLOWED_TRANSITIONS: dict[WorkflowState, set[WorkflowState]] = {
    WorkflowState.RECEIVED: {WorkflowState.NORMALIZED, WorkflowState.FAILED},
    WorkflowState.NORMALIZED: {WorkflowState.INVESTIGATING, WorkflowState.FAILED},
    WorkflowState.INVESTIGATING: {WorkflowState.CORRELATED, WorkflowState.FAILED},
    WorkflowState.CORRELATED: {WorkflowState.MAPPED, WorkflowState.FAILED},
    WorkflowState.MAPPED: {WorkflowState.RULE_GENERATED, WorkflowState.FAILED},
    WorkflowState.RULE_GENERATED: {WorkflowState.VALIDATING, WorkflowState.FAILED},
    WorkflowState.VALIDATING: {
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.RULE_GENERATED,
        WorkflowState.FAILED,
    },
    WorkflowState.AWAITING_APPROVAL: {
        WorkflowState.PUBLISHED,
        WorkflowState.FAILED,
    },
    WorkflowState.PUBLISHED: {WorkflowState.MONITORING, WorkflowState.FAILED},
    WorkflowState.MONITORING: {WorkflowState.COMPLETED, WorkflowState.FAILED},
    WorkflowState.COMPLETED: set(),
    WorkflowState.FAILED: set(),
}


class InvalidTransition(ValueError):
    """Raised when a workflow attempts to skip a required control point."""


class Workflow:
    def __init__(self, state: WorkflowState = WorkflowState.RECEIVED) -> None:
        self.state = state
        self.history = [state]

    def transition(self, target: WorkflowState) -> WorkflowState:
        if target not in ALLOWED_TRANSITIONS[self.state]:
            raise InvalidTransition(f"cannot transition from {self.state} to {target}")
        self.state = target
        self.history.append(target)
        return self.state
