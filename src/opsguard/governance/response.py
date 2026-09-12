"""Human approval gate and side-effect-free response execution."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import NAMESPACE_URL, uuid5

from opsguard.domain.models import BehaviorChain, Event
from opsguard.tools.response_simulator import ResponseSimulator

from .models import (
    ApprovalDecision,
    ResponseAction,
    ResponseActionType,
    ResponseExecution,
    ResponseProposal,
    RiskAssessment,
    RiskLevel,
)


class ApprovalError(PermissionError):
    """Base class for approval gate failures."""


class ApprovalRequiredError(ApprovalError):
    """Raised when no human decision is attached."""


class ApprovalDeniedError(ApprovalError):
    """Raised when the human decision rejects the scope."""


class ApprovalScopeError(ApprovalError):
    """Raised when a decision belongs to another investigation scope."""


class ApprovalGate:
    def authorize(
        self,
        proposal: ResponseProposal,
        approval: ApprovalDecision | None,
    ) -> ApprovalDecision:
        if approval is None:
            raise ApprovalRequiredError("explicit human approval is required")
        if approval.scope_id != proposal.scope_id:
            raise ApprovalScopeError(
                f"approval scope {approval.scope_id} does not match {proposal.scope_id}"
            )
        if not approval.approved:
            raise ApprovalDeniedError(f"approval denied by {approval.actor}")
        return approval


class ResponsePlanner:
    """Create deterministic containment proposals from chain entities."""

    def plan(
        self,
        assessment: RiskAssessment,
        chain: BehaviorChain,
        events: Sequence[Event],
    ) -> ResponseProposal:
        chain_events = [event for event in events if event.event_id in chain.event_ids]
        technique_ids = {mapping.technique_id for mapping in chain.mappings}
        actions: list[ResponseAction] = []
        if assessment.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            hosts = list(dict.fromkeys(event.host for event in chain_events if event.host))
            if hosts:
                actions.append(
                    ResponseAction(
                        action_type=ResponseActionType.ISOLATE_HOST,
                        target=hosts[0],
                        reason="Contain the host associated with the high-risk chain.",
                    )
                )
            domains = list(
                dict.fromkeys(event.domain for event in chain_events if event.domain)
            )
            actions.extend(
                ResponseAction(
                    action_type=ResponseActionType.BLOCK_DOMAIN,
                    target=domain,
                    reason="Block an external domain observed in the behavior chain.",
                )
                for domain in domains
            )
            if (
                assessment.level == RiskLevel.CRITICAL
                or "T1021.004" in technique_ids
            ):
                users = list(
                    dict.fromkeys(event.user for event in chain_events if event.user)
                )
                if users:
                    actions.append(
                        ResponseAction(
                            action_type=ResponseActionType.DISABLE_USER,
                            target=users[0],
                            reason="Disable the identity involved in high-risk access.",
                        )
                    )

        signature = ",".join(
            f"{action.action_type.value}:{action.target}" for action in actions
        )
        proposal_id = str(
            uuid5(
                NAMESPACE_URL,
                f"opsguard:response:{assessment.scope_id}:{signature}",
            )
        )
        return ResponseProposal(
            proposal_id=proposal_id,
            scope_id=assessment.scope_id,
            risk=assessment,
            actions=actions,
            requires_approval=bool(actions),
        )


class ResponseExecutor:
    def __init__(
        self,
        simulator: ResponseSimulator | None = None,
        approval_gate: ApprovalGate | None = None,
    ) -> None:
        self.simulator = simulator or ResponseSimulator()
        self.approval_gate = approval_gate or ApprovalGate()

    def execute(
        self,
        proposal: ResponseProposal,
        approval: ApprovalDecision | None,
    ) -> list[ResponseExecution]:
        self.approval_gate.authorize(proposal, approval)
        executions = []
        for action in proposal.actions:
            if action.action_type == ResponseActionType.ISOLATE_HOST:
                result = self.simulator.isolate_host(action.target)
            elif action.action_type == ResponseActionType.DISABLE_USER:
                result = self.simulator.disable_user(action.target)
            else:
                result = self.simulator.block_domain(action.target)
            executions.append(
                ResponseExecution(
                    action=action,
                    status="simulated",
                    result=result,
                )
            )
        return executions
