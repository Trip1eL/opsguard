"""Constrained in-process replay sandbox for candidate Sigma rules."""

from __future__ import annotations

from collections.abc import Iterable
from time import perf_counter

from opsguard.data.fixtures import DatasetRecord
from opsguard.domain.models import DetectionRule, RuleStatus, ValidationResult

from .models import (
    RuleValidationReport,
    ValidationSample,
    ValidationThresholds,
)
from .sigma import SigmaRuleMatcher


class OfflineRuleSandbox:
    """Replay a safe compiled predicate without shell, network, or file writes."""

    def __init__(
        self,
        matcher: SigmaRuleMatcher | None = None,
        thresholds: ValidationThresholds | None = None,
    ) -> None:
        self.matcher = matcher or SigmaRuleMatcher()
        self.thresholds = thresholds or ValidationThresholds()

    def replay(
        self,
        rule: DetectionRule,
        records: Iterable[DatasetRecord],
        dataset: str,
        target_event_ids: set[str] | None = None,
    ) -> RuleValidationReport:
        compiled = self.matcher.compile(rule)
        scoped_records = self._scope_records(list(records), target_event_ids)
        if not scoped_records:
            raise ValueError("sandbox dataset contains no evaluation records")
        if not any(record.event_label == "suspicious" for record in scoped_records):
            raise ValueError("sandbox dataset contains no target positive records")

        started = perf_counter()
        outcomes = [
            (record, compiled.matches(record.event)) for record in scoped_records
        ]
        latency_ms = (perf_counter() - started) * 1000

        true_positive = sum(
            matched and record.event_label == "suspicious"
            for record, matched in outcomes
        )
        false_positive = sum(
            matched and record.event_label == "benign"
            for record, matched in outcomes
        )
        false_negative = sum(
            not matched and record.event_label == "suspicious"
            for record, matched in outcomes
        )
        true_negative = sum(
            not matched and record.event_label == "benign"
            for record, matched in outcomes
        )
        precision = _ratio(true_positive, true_positive + false_positive)
        recall = _ratio(true_positive, true_positive + false_negative)
        f1 = _ratio(2 * precision * recall, precision + recall)
        false_positive_rate = _ratio(
            false_positive,
            false_positive + true_negative,
        )
        passed = (
            precision >= self.thresholds.min_precision
            and recall >= self.thresholds.min_recall
            and false_positive_rate <= self.thresholds.max_false_positive_rate
            and latency_ms <= self.thresholds.max_latency_ms
        )
        result = ValidationResult(
            rule_id=rule.rule_id,
            dataset=dataset,
            true_positive=true_positive,
            false_positive=false_positive,
            false_negative=false_negative,
            precision=precision,
            recall=recall,
            f1=f1,
            passed=passed,
        )
        validated_rule = rule.model_copy(
            update={"status": RuleStatus.VALIDATED if passed else RuleStatus.DRAFT}
        )
        false_positives = [
            _sample(record, matched)
            for record, matched in outcomes
            if matched and record.event_label == "benign"
        ]
        false_negatives = [
            _sample(record, matched)
            for record, matched in outcomes
            if not matched and record.event_label == "suspicious"
        ]
        return RuleValidationReport(
            rule=validated_rule,
            result=result,
            true_negative=true_negative,
            false_positive_rate=false_positive_rate,
            execution_latency_ms=latency_ms,
            evaluated_event_ids=[record.event.event_id for record, _ in outcomes],
            matched_event_ids=[
                record.event.event_id for record, matched in outcomes if matched
            ],
            false_positive_samples=false_positives,
            false_negative_samples=false_negatives,
            suggestions=self._suggestions(
                false_positives,
                false_negatives,
                latency_ms,
            ),
        )

    @staticmethod
    def _scope_records(
        records: list[DatasetRecord],
        target_event_ids: set[str] | None,
    ) -> list[DatasetRecord]:
        if target_event_ids is None:
            return records
        return [
            record
            for record in records
            if record.event_label == "benign"
            or record.event.event_id in target_event_ids
        ]

    def _suggestions(
        self,
        false_positives: list[ValidationSample],
        false_negatives: list[ValidationSample],
        latency_ms: float,
    ) -> list[str]:
        suggestions = []
        if false_positives:
            suggestions.append(
                "Add change-ticket, trusted-source, or process-context exclusions "
                "for the reported false-positive samples."
            )
        if false_negatives:
            suggestions.append(
                "Broaden the relevant selection fields using evidence from the "
                "reported false-negative samples."
            )
        if latency_ms > self.thresholds.max_latency_ms:
            suggestions.append(
                "Reduce broad selections or add an indexed action/process prefilter."
            )
        return suggestions


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _sample(record: DatasetRecord, matched: bool) -> ValidationSample:
    return ValidationSample(
        event_id=record.event.event_id,
        case_id=record.case_id,
        scenario=record.scenario,
        expected_label=record.event_label,
        matched=matched,
    )
