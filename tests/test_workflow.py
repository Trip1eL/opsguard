import pytest

from opsguard.agents.workflow import InvalidTransition, Workflow, WorkflowState


def test_workflow_requires_validation_before_approval() -> None:
    workflow = Workflow()
    workflow.transition(WorkflowState.NORMALIZED)
    workflow.transition(WorkflowState.INVESTIGATING)
    workflow.transition(WorkflowState.CORRELATED)
    workflow.transition(WorkflowState.MAPPED)
    workflow.transition(WorkflowState.RULE_GENERATED)

    with pytest.raises(InvalidTransition):
        workflow.transition(WorkflowState.PUBLISHED)


def test_approved_workflow_can_be_published() -> None:
    workflow = Workflow()
    for state in [
        WorkflowState.NORMALIZED,
        WorkflowState.INVESTIGATING,
        WorkflowState.CORRELATED,
        WorkflowState.MAPPED,
        WorkflowState.RULE_GENERATED,
        WorkflowState.VALIDATING,
        WorkflowState.AWAITING_APPROVAL,
    ]:
        workflow.transition(state)

    workflow.transition(WorkflowState.PUBLISHED)
    assert workflow.state == WorkflowState.PUBLISHED


def test_failed_workflow_is_terminal() -> None:
    workflow = Workflow()
    workflow.transition(WorkflowState.FAILED)

    with pytest.raises(InvalidTransition):
        workflow.transition(WorkflowState.NORMALIZED)
