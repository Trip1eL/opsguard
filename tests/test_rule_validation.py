from pathlib import Path

import pytest
import yaml

from opsguard.attack import AttackTechniqueMapper, TechniqueCatalog
from opsguard.correlation import BehaviorCorrelator
from opsguard.data import load_dataset, load_manifest
from opsguard.detection import DetectionEngine
from opsguard.domain.models import DetectionRule, RuleStatus
from opsguard.rules import (
    OfflineRuleSandbox,
    SigmaRuleGenerator,
    SigmaRuleMatcher,
    SigmaRuleValidator,
    SigmaValidationError,
)

ROOT = Path(__file__).parents[1]
CATALOG = TechniqueCatalog.from_json(
    ROOT / "knowledge" / "attack" / "techniques.json"
)


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
    return AttackTechniqueMapper(CATALOG).map_chain(chain, events)


def test_sigma_generation_is_stable_versioned_and_parseable() -> None:
    chain = _mapped_chain("alert-scheduled_task")
    generator = SigmaRuleGenerator()

    first = generator.generate(chain, version=1)
    second = generator.generate(chain, version=2)
    document = SigmaRuleValidator().parse(second)

    assert first.rule_id == second.rule_id
    assert first.version == 1
    assert second.version == 2
    assert document.metadata["version"] == 2
    assert set(second.technique_ids) == {"T1021.004", "T1053.003", "T1105"}
    assert document.condition == "1 of selection_*"


def test_generated_rule_matches_chain_evidence_without_benign_events() -> None:
    chain = _mapped_chain("alert-scheduled_task")
    compiled = SigmaRuleMatcher().compile(SigmaRuleGenerator().generate(chain))
    records = _records()

    matched = {
        record.event.event_id
        for record in records
        if compiled.matches(record.event)
    }

    assert set(chain.event_ids) <= matched
    assert not matched & {
        record.event.event_id
        for record in records
        if record.event_label == "benign"
    }


def test_sandbox_validates_rule_and_updates_only_candidate_status() -> None:
    chain = _mapped_chain("alert-scheduled_task")
    rule = SigmaRuleGenerator().generate(chain)
    report = OfflineRuleSandbox().replay(
        rule,
        _records(),
        "opsguard-fixtures",
        set(chain.event_ids),
    )

    assert report.result.passed is True
    assert report.result.true_positive == 3
    assert report.true_negative == 3
    assert report.result.false_positive == 0
    assert report.result.false_negative == 0
    assert report.result.precision == 1.0
    assert report.result.recall == 1.0
    assert report.result.f1 == 1.0
    assert report.false_positive_rate == 0.0
    assert report.rule.status == RuleStatus.VALIDATED
    assert rule.status == RuleStatus.DRAFT
    assert report.suggestions == []


def test_sandbox_returns_false_negative_samples_and_adjustment_advice() -> None:
    chain = _mapped_chain("alert-web_child")
    report = OfflineRuleSandbox().replay(
        SigmaRuleGenerator().generate(chain),
        _records(),
        "opsguard-fixtures",
        set(chain.event_ids),
    )

    assert report.result.passed is False
    assert report.result.false_negative == 1
    assert report.false_negative_samples[0].event_id == "evt-web-001"
    assert report.rule.status == RuleStatus.DRAFT
    assert any("Broaden" in suggestion for suggestion in report.suggestions)


def test_sandbox_reports_false_positive_samples() -> None:
    rule_id = "5e83d67a-6c93-4b05-9d79-c69331d7ab88"
    content = yaml.safe_dump(
        {
            "title": "Broad SSH login rule",
            "id": rule_id,
            "logsource": {"product": "opsguard"},
            "detection": {
                "selection_login": {"action": "ssh_login"},
                "condition": "1 of selection_*",
            },
        },
        sort_keys=False,
    )
    rule = DetectionRule(
        rule_id=rule_id,
        version=1,
        name="Broad SSH login rule",
        content=content,
    )
    report = OfflineRuleSandbox().replay(
        rule,
        _records(),
        "opsguard-fixtures",
        {"evt-ssh-001"},
    )

    assert report.result.passed is False
    assert report.result.false_positive == 1
    assert report.false_positive_samples[0].event_id == "evt-release-001"
    assert any("exclusions" in suggestion for suggestion in report.suggestions)


def test_validator_rejects_non_allowlisted_fields_and_conditions() -> None:
    rule_id = "852ffc16-57f4-466b-86fc-ebf947984bc8"
    document = {
        "title": "Unsafe rule",
        "id": rule_id,
        "logsource": {"product": "opsguard"},
        "detection": {
            "selection_unsafe": {"raw_log|contains": "password"},
            "condition": "selection_unsafe",
        },
    }
    rule = DetectionRule(
        rule_id=rule_id,
        version=1,
        name="Unsafe rule",
        content=yaml.safe_dump(document),
    )

    with pytest.raises(SigmaValidationError, match="only the condition"):
        SigmaRuleValidator().parse(rule)

    document["detection"]["condition"] = "1 of selection_*"
    rule.content = yaml.safe_dump(document)
    with pytest.raises(SigmaValidationError, match="not allow-listed"):
        SigmaRuleValidator().parse(rule)


def test_safe_yaml_rejects_object_construction_tags() -> None:
    rule = DetectionRule(
        rule_id="80bba8b4-aec3-46fc-8b41-6cd720577b5d",
        version=1,
        name="Object construction attempt",
        content="!!python/object/apply:os.system ['echo unsafe']",
    )

    with pytest.raises(SigmaValidationError, match="invalid Sigma YAML"):
        SigmaRuleValidator().parse(rule)
