"""Human-gated rule lifecycle with canary evaluation and automatic rollback."""

from __future__ import annotations

from uuid import uuid4

from opsguard.domain.models import DetectionRule, RuleStatus

from .audit import InMemoryAuditLog
from .models import (
    ApprovalDecision,
    AuditAction,
    AuditRecord,
    CanaryMetrics,
    CanaryPolicy,
)


class RuleLifecycleError(ValueError):
    """Raised when a rule transition skips a required governance control."""


class RuleLifecycleManager:
    def __init__(
        self,
        audit_log: InMemoryAuditLog | None = None,
        canary_policy: CanaryPolicy | None = None,
    ) -> None:
        self.audit_log = audit_log or InMemoryAuditLog()
        self.canary_policy = canary_policy or CanaryPolicy()

    def start_canary(
        self,
        rule: DetectionRule,
        approval: ApprovalDecision,
        scope_id: str,
    ) -> DetectionRule:
        if approval.scope_id != scope_id or not approval.approved:
            self._rejected(
                rule,
                scope_id,
                approval.actor,
                "canary requires an approved decision for the same scope",
            )
            raise RuleLifecycleError(
                "canary requires an approved decision for the same scope"
            )
        return self._transition(
            rule,
            RuleStatus.CANARY,
            {RuleStatus.VALIDATED},
            scope_id,
            approval.actor,
            f"approved for canary: {approval.reason}",
        )

    def evaluate_canary(
        self,
        rule: DetectionRule,
        metrics: CanaryMetrics,
        scope_id: str,
        actor: str = "opsguard-policy",
    ) -> DetectionRule:
        if rule.status != RuleStatus.CANARY:
            self._rejected(
                rule,
                scope_id,
                actor,
                "canary metrics can only be applied to a canary rule",
            )
            raise RuleLifecycleError(
                "canary metrics can only be applied to a canary rule"
            )

        breaches = self._breaches(metrics)
        self.audit_log.append(
            AuditRecord(
                audit_id=str(uuid4()),
                scope_id=scope_id,
                action=AuditAction.CANARY_EVALUATED,
                actor=actor,
                resource_id=self._resource_id(rule),
                reason="canary metrics evaluated",
                metadata={
                    "healthy": not breaches,
                    "breaches": breaches,
                    "metrics": metrics.model_dump(mode="json"),
                },
            )
        )
        if breaches:
            return self._transition(
                rule,
                RuleStatus.ROLLED_BACK,
                {RuleStatus.CANARY},
                scope_id,
                actor,
                f"automatic rollback: {'; '.join(breaches)}",
            )
        return self._transition(
            rule,
            RuleStatus.ACTIVE,
            {RuleStatus.CANARY},
            scope_id,
            actor,
            "canary metrics passed policy thresholds",
        )

    def rollback(
        self,
        rule: DetectionRule,
        scope_id: str,
        actor: str,
        reason: str,
    ) -> DetectionRule:
        if not reason.strip():
            raise ValueError("rollback reason must not be empty")
        return self._transition(
            rule,
            RuleStatus.ROLLED_BACK,
            {RuleStatus.CANARY, RuleStatus.ACTIVE},
            scope_id,
            actor,
            reason,
        )

    def _breaches(self, metrics: CanaryMetrics) -> list[str]:
        policy = self.canary_policy
        breaches = []
        if metrics.evaluated_events < policy.min_evaluated_events:
            breaches.append(
                f"evaluated_events {metrics.evaluated_events} "
                f"< {policy.min_evaluated_events}"
            )
        if metrics.false_positive_rate > policy.max_false_positive_rate:
            breaches.append(
                f"false_positive_rate {metrics.false_positive_rate:.4f} "
                f"> {policy.max_false_positive_rate:.4f}"
            )
        if metrics.error_rate > policy.max_error_rate:
            breaches.append(
                f"error_rate {metrics.error_rate:.4f} "
                f"> {policy.max_error_rate:.4f}"
            )
        if metrics.p95_latency_ms > policy.max_p95_latency_ms:
            breaches.append(
                f"p95_latency_ms {metrics.p95_latency_ms:.2f} "
                f"> {policy.max_p95_latency_ms:.2f}"
            )
        return breaches

    def _transition(
        self,
        rule: DetectionRule,
        target: RuleStatus,
        allowed_sources: set[RuleStatus],
        scope_id: str,
        actor: str,
        reason: str,
    ) -> DetectionRule:
        if rule.status not in allowed_sources:
            message = f"cannot transition rule from {rule.status} to {target}"
            self._rejected(rule, scope_id, actor, message)
            raise RuleLifecycleError(message)
        transitioned = rule.model_copy(update={"status": target})
        self.audit_log.append(
            AuditRecord(
                audit_id=str(uuid4()),
                scope_id=scope_id,
                action=AuditAction.RULE_TRANSITIONED,
                actor=actor,
                resource_id=self._resource_id(rule),
                before=rule.status.value,
                after=target.value,
                reason=reason,
            )
        )
        return transitioned

    def _rejected(
        self,
        rule: DetectionRule,
        scope_id: str,
        actor: str,
        reason: str,
    ) -> None:
        self.audit_log.append(
            AuditRecord(
                audit_id=str(uuid4()),
                scope_id=scope_id,
                action=AuditAction.RULE_TRANSITION_REJECTED,
                actor=actor,
                resource_id=self._resource_id(rule),
                before=rule.status.value,
                reason=reason,
            )
        )

    @staticmethod
    def _resource_id(rule: DetectionRule) -> str:
        return f"rule:{rule.rule_id}:v{rule.version}"
