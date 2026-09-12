from datetime import UTC, datetime
from pathlib import Path

import pytest

from opsguard.attack import AttackTechniqueMapper, TechniqueCatalog
from opsguard.correlation import BehaviorCorrelator
from opsguard.data import load_dataset, load_manifest
from opsguard.detection import DetectionEngine
from opsguard.domain.models import RuleStatus
from opsguard.governance import (
    ApprovalDecision,
    AuditAction,
    CanaryMetrics,
    GovernanceCoordinator,
    GovernanceStatus,
    RiskAssessor,
    RiskLevel,
    RuleLifecycleError,
    RuleLifecycleManager,
)
from opsguard.rules import OfflineRuleSandbox, SigmaRuleGenerator

ROOT = Path(__file__).parents[1]


def _records():
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    return [
        record
        for item in manifest.cases
        for record in load_dataset(ROOT / "datasets" / item["file"])
    ]


def _investigation(alert_prefix: str):
    records = _records()
    events = [record.event for record in records]
    alert = next(
        alert
        for alert in DetectionEngine().detect(events)
        if alert.alert_id.startswith(alert_prefix)
    )
    chain = BehaviorCorrelator().correlate(alert, events).chain
    catalog = TechniqueCatalog.from_json(
        ROOT / "knowledge" / "attack" / "techniques.json"
    )
    chain = AttackTechniqueMapper(catalog).map_chain(chain, events)
    rule = SigmaRuleGenerator().generate(chain)
    validation = OfflineRuleSandbox().replay(
        rule,
        records,
        "opsguard-fixtures",
        set(chain.event_ids),
    )
    return alert, chain, events, validation


def _approval(scope_id: str, approved: bool = True) -> ApprovalDecision:
    return ApprovalDecision(
        approval_id=f"approval-{scope_id}",
        scope_id=scope_id,
        actor="soc-lead",
        approved=approved,
        reason="reviewed evidence and validation metrics",
        created_at=datetime.now(UTC),
    )


def _healthy_metrics() -> CanaryMetrics:
    return CanaryMetrics(
        evaluated_events=1000,
        false_positive_rate=0.01,
        error_rate=0.001,
        p95_latency_ms=25,
    )


def test_risk_assessment_grades_web_shell_as_critical() -> None:
    alert, chain, _, _ = _investigation("alert-web_child")
    assessment = RiskAssessor().assess(chain.case_id, [alert], chain)

    assert assessment.level == RiskLevel.CRITICAL
    assert assessment.requires_human_approval is True
    assert any("web server" in factor for factor in assessment.factors)


def test_missing_approval_blocks_rule_and_response_actions() -> None:
    alert, chain, events, validation = _investigation("alert-scheduled_task")
    coordinator = GovernanceCoordinator()
    outcome = coordinator.govern([alert], chain, events, validation)

    assert outcome.status == GovernanceStatus.AWAITING_APPROVAL
    assert outcome.rule.status == RuleStatus.VALIDATED
    assert outcome.response_executions == []
    assert coordinator.response_executor.simulator.state.isolated_hosts == set()
    assert outcome.audit_records[-1].action == AuditAction.APPROVAL_REQUIRED


def test_denied_or_wrong_scope_approval_cannot_execute_actions() -> None:
    alert, chain, events, validation = _investigation("alert-scheduled_task")
    for approval in (
        _approval(chain.case_id, approved=False),
        _approval("another-case"),
    ):
        coordinator = GovernanceCoordinator()
        outcome = coordinator.govern(
            [alert],
            chain,
            events,
            validation,
            approval,
        )

        assert outcome.status == GovernanceStatus.DENIED
        assert outcome.rule.status == RuleStatus.VALIDATED
        assert outcome.response_executions == []
        assert coordinator.response_executor.simulator.state.isolated_hosts == set()
        assert any(
            record.action == AuditAction.RESPONSE_BLOCKED
            for record in outcome.audit_records
        )


def test_approved_healthy_canary_activates_rule_and_simulates_response() -> None:
    alert, chain, events, validation = _investigation("alert-scheduled_task")
    coordinator = GovernanceCoordinator()
    outcome = coordinator.govern(
        [alert],
        chain,
        events,
        validation,
        _approval(chain.case_id),
        _healthy_metrics(),
    )

    assert outcome.status == GovernanceStatus.ACTIVE
    assert outcome.rule.status == RuleStatus.ACTIVE
    assert validation.rule.status == RuleStatus.VALIDATED
    assert {item.action.action_type.value for item in outcome.response_executions} == {
        "isolate_host",
        "disable_user",
        "block_domain",
    }
    state = coordinator.response_executor.simulator.state
    assert state.isolated_hosts == {"web-03"}
    assert state.disabled_users == {"deploy"}
    assert state.blocked_domains == {"updates-example.net"}
    transitions = [
        (record.before, record.after)
        for record in outcome.audit_records
        if record.action == AuditAction.RULE_TRANSITIONED
    ]
    assert transitions == [("validated", "canary"), ("canary", "active")]

    rolled_back = coordinator.lifecycle.rollback(
        outcome.rule,
        chain.case_id,
        "soc-lead",
        "manual rollback after post-deployment review",
    )
    assert rolled_back.status == RuleStatus.ROLLED_BACK
    assert coordinator.audit_log.records(chain.case_id)[-1].before == "active"
    assert coordinator.audit_log.records(chain.case_id)[-1].after == "rolled_back"


def test_approval_without_metrics_stops_at_canary() -> None:
    alert, chain, events, validation = _investigation("alert-scheduled_task")
    outcome = GovernanceCoordinator().govern(
        [alert],
        chain,
        events,
        validation,
        _approval(chain.case_id),
    )

    assert outcome.status == GovernanceStatus.CANARY
    assert outcome.rule.status == RuleStatus.CANARY
    assert not any(
        record.after == "active"
        for record in outcome.audit_records
        if record.action == AuditAction.RULE_TRANSITIONED
    )


def test_unhealthy_canary_is_automatically_rolled_back_with_breaches() -> None:
    alert, chain, events, validation = _investigation("alert-scheduled_task")
    metrics = CanaryMetrics(
        evaluated_events=500,
        false_positive_rate=0.20,
        error_rate=0.03,
        p95_latency_ms=350,
    )
    outcome = GovernanceCoordinator().govern(
        [alert],
        chain,
        events,
        validation,
        _approval(chain.case_id),
        metrics,
    )

    assert outcome.status == GovernanceStatus.ROLLED_BACK
    assert outcome.rule.status == RuleStatus.ROLLED_BACK
    evaluation = next(
        record
        for record in outcome.audit_records
        if record.action == AuditAction.CANARY_EVALUATED
    )
    assert evaluation.metadata["healthy"] is False
    assert len(evaluation.metadata["breaches"]) == 3
    assert outcome.audit_records[-1].after == "rolled_back"


def test_draft_rule_cannot_skip_validation_and_enter_canary() -> None:
    _, chain, _, validation = _investigation("alert-scheduled_task")
    lifecycle = RuleLifecycleManager()
    draft = validation.rule.model_copy(update={"status": RuleStatus.DRAFT})

    with pytest.raises(RuleLifecycleError, match="cannot transition"):
        lifecycle.start_canary(draft, _approval(chain.case_id), chain.case_id)

    records = lifecycle.audit_log.records(chain.case_id)
    assert records[-1].action == AuditAction.RULE_TRANSITION_REJECTED
    assert records[-1].before == "draft"
