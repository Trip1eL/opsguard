from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from opsguard.attack import AttackTechniqueMapper, TechniqueCatalog
from opsguard.correlation import BehaviorCorrelator
from opsguard.data import load_dataset, load_manifest
from opsguard.detection import DetectionEngine
from opsguard.domain.models import DetectionRule, RuleStatus
from opsguard.feedback import (
    FeedbackConflictError,
    FeedbackFlywheel,
    FeedbackKind,
    FeedbackRecord,
    InMemoryFeedbackStore,
)
from opsguard.rules import SigmaRuleGenerator, SigmaRuleValidator

ROOT = Path(__file__).parents[1]


def _records():
    manifest = load_manifest(ROOT / "datasets" / "manifest.json")
    return [
        record
        for item in manifest.cases
        for record in load_dataset(ROOT / "datasets" / item["file"])
    ]


def _mapped_chain(alert_prefix: str):
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
    return AttackTechniqueMapper(catalog).map_chain(chain, events)


def _feedback(
    rule: DetectionRule,
    event_id: str,
    kind: FeedbackKind,
    feedback_id: str = "feedback-001",
) -> FeedbackRecord:
    return FeedbackRecord(
        feedback_id=feedback_id,
        investigation_id="investigation-001",
        rule_id=rule.rule_id,
        rule_version=rule.version,
        event_id=event_id,
        kind=kind,
        actor="soc-analyst",
        comment="verified against the event evidence",
        created_at=datetime.now(UTC),
    )


def _broad_ssh_rule() -> DetectionRule:
    rule_id = "7b64632d-f451-47c5-a728-9d6b0c57aba6"
    content = yaml.safe_dump(
        {
            "title": "Broad SSH login rule",
            "id": rule_id,
            "logsource": {"product": "opsguard"},
            "detection": {
                "selection_login": {"action": "ssh_login"},
                "condition": "1 of selection_*",
            },
            "x_opsguard": {
                "version": 1,
                "event_ids": ["evt-ssh-001"],
            },
        },
        sort_keys=False,
    )
    return DetectionRule(
        rule_id=rule_id,
        version=1,
        name="Broad SSH login rule",
        content=content,
    )


def test_feedback_store_is_idempotent_and_rejects_conflicts() -> None:
    rule = _broad_ssh_rule()
    store = InMemoryFeedbackStore()
    record = _feedback(rule, "evt-release-001", FeedbackKind.FALSE_POSITIVE)

    store.add(record)
    store.add(record)
    assert store.list(rule.rule_id, 1) == [record]

    conflicting = record.model_copy(update={"comment": "different evidence"})
    with pytest.raises(FeedbackConflictError):
        store.add(conflicting)


def test_false_positive_feedback_creates_filter_and_improves_metrics() -> None:
    rule = _broad_ssh_rule()
    flywheel = FeedbackFlywheel()
    feedback = _feedback(
        rule,
        "evt-release-001",
        FeedbackKind.FALSE_POSITIVE,
    )
    flywheel.store.add(feedback)

    proposal = flywheel.evolve(rule, _records())
    document = SigmaRuleValidator().parse(proposal.candidate_rule)

    assert proposal.candidate_rule.rule_id == rule.rule_id
    assert proposal.candidate_rule.version == 2
    assert proposal.candidate_rule.status == RuleStatus.DRAFT
    assert document.condition == "1 of selection_* and not 1 of filter_*"
    assert document.filters
    assert proposal.baseline_validation.result.false_positive == 1
    assert proposal.candidate_validation.result.false_positive == 0
    assert proposal.metric_deltas["precision"] == 0.5
    assert proposal.metric_deltas["f1"] > 0
    assert proposal.recommended is True
    assert proposal.candidate_validation.rule.status == RuleStatus.VALIDATED


def test_false_negative_feedback_adds_selection_and_improves_recall() -> None:
    chain = _mapped_chain("alert-web_child")
    rule = SigmaRuleGenerator().generate(chain)
    flywheel = FeedbackFlywheel()
    flywheel.store.add(
        _feedback(
            rule,
            "evt-web-001",
            FeedbackKind.FALSE_NEGATIVE,
            "feedback-web-fn",
        )
    )

    proposal = flywheel.evolve(rule, _records(), target_event_ids=set(chain.event_ids))

    assert proposal.baseline_validation.result.false_negative == 1
    assert proposal.candidate_validation.result.false_negative == 0
    assert proposal.metric_deltas["recall"] > 0
    assert proposal.candidate_validation.result.f1 == 1.0
    assert proposal.recommended is True


def test_true_positive_confirmation_does_not_auto_recommend_same_rule() -> None:
    chain = _mapped_chain("alert-scheduled_task")
    rule = SigmaRuleGenerator().generate(chain)
    flywheel = FeedbackFlywheel()
    flywheel.store.add(
        _feedback(
            rule,
            "evt-ssh-001",
            FeedbackKind.TRUE_POSITIVE,
            "feedback-ssh-tp",
        )
    )

    proposal = flywheel.evolve(rule, _records(), target_event_ids=set(chain.event_ids))

    assert proposal.metric_deltas["f1"] == 0
    assert proposal.recommended is False
    assert proposal.candidate_rule.status == RuleStatus.DRAFT
    assert "not approved automatically" in proposal.rationale[-1]


def test_feedback_for_another_version_cannot_mutate_rule() -> None:
    rule = _broad_ssh_rule()
    flywheel = FeedbackFlywheel()
    record = _feedback(rule, "evt-release-001", FeedbackKind.FALSE_POSITIVE)
    flywheel.store.add(record.model_copy(update={"rule_version": 2}))

    with pytest.raises(ValueError, match="no feedback applies"):
        flywheel.evolve(rule, _records())
