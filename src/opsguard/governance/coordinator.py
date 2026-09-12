"""Coordinate risk, approval, simulation, canary, and audit decisions."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import uuid4

from opsguard.domain.cases import Alert
from opsguard.domain.models import BehaviorChain, Event, RuleStatus
from opsguard.rules import RuleValidationReport

from .audit import InMemoryAuditLog
from .lifecycle import RuleLifecycleManager
from .models import (
    ApprovalDecision,
    AuditAction,
    AuditRecord,
    CanaryMetrics,
    GovernanceOutcome,
    GovernanceStatus,
    ResponseExecution,
)
from .response import ApprovalError, ApprovalGate, ResponseExecutor, ResponsePlanner
from .risk import RiskAssessor


class GovernanceCoordinator:
    def __init__(
        self,
        audit_log: InMemoryAuditLog | None = None,
        risk_assessor: RiskAssessor | None = None,
        response_planner: ResponsePlanner | None = None,
        response_executor: ResponseExecutor | None = None,
        lifecycle: RuleLifecycleManager | None = None,
    ) -> None:
        if (
            lifecycle is not None
            and audit_log is not None
            and lifecycle.audit_log is not audit_log
        ):
            raise ValueError("coordinator and lifecycle must share one audit log")
        self.audit_log = (
            lifecycle.audit_log
            if lifecycle is not None
            else audit_log or InMemoryAuditLog()
        )
        self.risk_assessor = risk_assessor or RiskAssessor()
        self.response_planner = response_planner or ResponsePlanner()
        self.response_executor = response_executor or ResponseExecutor()
        self.lifecycle = lifecycle or RuleLifecycleManager(self.audit_log)
        self.approval_gate = ApprovalGate()

    def govern(
        self,
        alerts: Sequence[Alert],
        chain: BehaviorChain,
        events: Sequence[Event],
        validation: RuleValidationReport,
        approval: ApprovalDecision | None = None,
        canary_metrics: CanaryMetrics | None = None,
    ) -> GovernanceOutcome:
        scope_id = chain.case_id
        existing_audit_ids = {
            record.audit_id for record in self.audit_log.records(scope_id)
        }
        assessment = self.risk_assessor.assess(scope_id, alerts, chain)
        proposal = self.response_planner.plan(assessment, chain, events)
        self._audit(
            scope_id,
            AuditAction.RISK_ASSESSED,
            "opsguard-risk",
            "deterministic risk factors evaluated",
            metadata=assessment.model_dump(mode="json"),
        )
        self._audit(
            scope_id,
            AuditAction.RESPONSE_PROPOSED,
            "opsguard-response",
            "simulated containment actions proposed",
            resource_id=proposal.proposal_id,
            metadata={
                "action_count": len(proposal.actions),
                "actions": [
                    action.model_dump(mode="json") for action in proposal.actions
                ],
            },
        )

        rule = validation.rule
        if not validation.result.passed or rule.status != RuleStatus.VALIDATED:
            self._audit(
                scope_id,
                AuditAction.RESPONSE_BLOCKED,
                "opsguard-policy",
                "rule validation did not pass",
                resource_id=proposal.proposal_id,
            )
            return self._outcome(
                GovernanceStatus.VALIDATION_FAILED,
                assessment,
                proposal,
                rule,
                existing_audit_ids,
            )

        if approval is None:
            self._audit(
                scope_id,
                AuditAction.APPROVAL_REQUIRED,
                "opsguard-policy",
                "human approval is required before response or canary",
                resource_id=proposal.proposal_id,
            )
            return self._outcome(
                GovernanceStatus.AWAITING_APPROVAL,
                assessment,
                proposal,
                rule,
                existing_audit_ids,
            )

        self._audit(
            scope_id,
            AuditAction.APPROVAL_RECORDED,
            approval.actor,
            approval.reason,
            resource_id=approval.approval_id,
            metadata={
                "approved": approval.approved,
                "approval_scope": approval.scope_id,
            },
        )
        try:
            self.approval_gate.authorize(proposal, approval)
        except ApprovalError as exc:
            self._audit(
                scope_id,
                AuditAction.RESPONSE_BLOCKED,
                "opsguard-policy",
                str(exc),
                resource_id=proposal.proposal_id,
            )
            return self._outcome(
                GovernanceStatus.DENIED,
                assessment,
                proposal,
                rule,
                existing_audit_ids,
                approval=approval,
            )

        rule = self.lifecycle.start_canary(rule, approval, scope_id)
        executions = self.response_executor.execute(proposal, approval)
        for execution in executions:
            self._audit_execution(scope_id, approval.actor, execution)

        status = GovernanceStatus.CANARY
        if canary_metrics is not None:
            rule = self.lifecycle.evaluate_canary(rule, canary_metrics, scope_id)
            status = (
                GovernanceStatus.ACTIVE
                if rule.status == RuleStatus.ACTIVE
                else GovernanceStatus.ROLLED_BACK
            )
        return self._outcome(
            status,
            assessment,
            proposal,
            rule,
            existing_audit_ids,
            approval=approval,
            canary_metrics=canary_metrics,
            executions=executions,
        )

    def _outcome(
        self,
        status: GovernanceStatus,
        assessment,
        proposal,
        rule,
        existing_audit_ids: set[str],
        approval: ApprovalDecision | None = None,
        canary_metrics: CanaryMetrics | None = None,
        executions: list[ResponseExecution] | None = None,
    ) -> GovernanceOutcome:
        new_records = [
            record
            for record in self.audit_log.records(assessment.scope_id)
            if record.audit_id not in existing_audit_ids
        ]
        return GovernanceOutcome(
            status=status,
            assessment=assessment,
            proposal=proposal,
            rule=rule,
            approval=approval,
            canary_metrics=canary_metrics,
            response_executions=executions or [],
            audit_records=new_records,
        )

    def _audit_execution(
        self,
        scope_id: str,
        actor: str,
        execution: ResponseExecution,
    ) -> None:
        self._audit(
            scope_id,
            AuditAction.RESPONSE_EXECUTED,
            actor,
            execution.result,
            resource_id=(
                f"{execution.action.action_type.value}:{execution.action.target}"
            ),
            metadata={"status": execution.status},
        )

    def _audit(
        self,
        scope_id: str,
        action: AuditAction,
        actor: str,
        reason: str,
        resource_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        self.audit_log.append(
            AuditRecord(
                audit_id=str(uuid4()),
                scope_id=scope_id,
                action=action,
                actor=actor,
                reason=reason,
                resource_id=resource_id,
                metadata=metadata or {},
            )
        )
