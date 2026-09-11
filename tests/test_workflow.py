import pytest

from opsguard.agents.workflow import InvalidTransition, Workflow, WorkflowState


def test_workflow_requires_validation_before_approval() -> None:
    workflow = Workflow()
    workflow.transition(WorkflowState.NORMALIZED)
    workflow.transition(WorkflowState.INVESTIGATING)
    workflow.transition(WorkflowState.CORRELATED)
    workflow.transition(WorkflowState.MAPPED)
    workflow.transition(WorkflowState.RULE_GENERATED)
    workflow.transition(WorkflowState.VALIDATING)
    workflow.transition(WorkflowState.AWAITING_APPROVAL)

    with pytest.raises(InvalidTransition):
        workflow.transition(WorkflowState.PUBLISHED)


def test_failed_workflow_is_terminal() -> None:
    workflow = Workflow()
    workflow.transition(WorkflowState.FAILED)

    with pytest.raises(InvalidTransition):
        workflow.transition(WorkflowState.NORMALIZED)

