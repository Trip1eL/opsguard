"""Create and evaluate candidate rule versions from verified human feedback."""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from typing import Any

import yaml

from opsguard.data.fixtures import DatasetRecord
from opsguard.domain.models import DetectionRule, Event, RuleStatus
from opsguard.rules import OfflineRuleSandbox, SigmaRuleValidator

from .models import FeedbackKind, FeedbackRecord, RuleEvolutionProposal
from .store import InMemoryFeedbackStore


class RuleCandidateOptimizer:
    """Apply feedback only through the constrained, revalidated Sigma AST."""

    def __init__(self, validator: SigmaRuleValidator | None = None) -> None:
        self.validator = validator or SigmaRuleValidator()

    def optimize(
        self,
        rule: DetectionRule,
        feedback: Iterable[FeedbackRecord],
        events: Iterable[Event],
    ) -> DetectionRule:
        self.validator.parse(rule)
        applicable = sorted(
            (
                item
                for item in feedback
                if item.rule_id == rule.rule_id
                and item.rule_version == rule.version
            ),
            key=lambda item: (item.created_at, item.feedback_id),
        )
        if not applicable:
            raise ValueError("no feedback applies to this rule version")

        document = yaml.safe_load(rule.content)
        detection = document["detection"]
        event_index = {event.event_id: event for event in events}
        applied_ids = []
        for index, item in enumerate(applicable, start=1):
            try:
                event = event_index[item.event_id]
            except KeyError as exc:
                raise ValueError(
                    f"feedback event not found: {item.event_id}"
                ) from exc
            suffix = f"{index:03d}_{item.feedback_id[-8:].replace('-', '_')}"
            if item.kind == FeedbackKind.FALSE_POSITIVE:
                detection[f"filter_feedback_{suffix}"] = (
                    self._false_positive_filter(event)
                )
            elif item.kind == FeedbackKind.FALSE_NEGATIVE:
                detection[f"selection_feedback_{suffix}"] = (
                    self._false_negative_selection(event)
                )
            applied_ids.append(item.feedback_id)

        if any(name.startswith("filter_") for name in detection):
            detection["condition"] = "1 of selection_* and not 1 of filter_*"
        metadata = deepcopy(document.get("x_opsguard", {}))
        metadata["version"] = rule.version + 1
        metadata["feedback_ids"] = applied_ids
        document["x_opsguard"] = metadata
        document["status"] = "experimental"
        document["description"] = (
            "Candidate evolved from human feedback; requires sandbox validation "
            "and a new approval cycle."
        )
        candidate = rule.model_copy(
            update={
                "version": rule.version + 1,
                "content": yaml.safe_dump(
                    document,
                    allow_unicode=False,
                    sort_keys=False,
                ),
                "status": RuleStatus.DRAFT,
            }
        )
        self.validator.parse(candidate)
        return candidate

    @staticmethod
    def _false_positive_filter(event: Event) -> dict[str, Any]:
        if "change_ticket" in event.attributes:
            return {"attributes.change_ticket|exists": True}
        if event.src_ip:
            return {"src_ip": event.src_ip}
        if event.domain:
            return {"domain": event.domain}
        result: dict[str, Any] = {"action": event.action}
        if event.host:
            result["host"] = event.host
        if event.process:
            result["process"] = event.process
        return result

    @staticmethod
    def _false_negative_selection(event: Event) -> dict[str, Any]:
        result: dict[str, Any] = {"action": event.action}
        for field in ("process", "parent_process", "src_ip", "domain"):
            value = getattr(event, field)
            if value:
                result[field] = value
        return result


class FeedbackFlywheel:
    def __init__(
        self,
        store: InMemoryFeedbackStore | None = None,
        optimizer: RuleCandidateOptimizer | None = None,
        sandbox: OfflineRuleSandbox | None = None,
    ) -> None:
        self.store = store or InMemoryFeedbackStore()
        self.optimizer = optimizer or RuleCandidateOptimizer()
        self.sandbox = sandbox or OfflineRuleSandbox()

    def evolve(
        self,
        rule: DetectionRule,
        records: Iterable[DatasetRecord],
        dataset: str = "opsguard-fixtures",
        target_event_ids: set[str] | None = None,
    ) -> RuleEvolutionProposal:
        records = list(records)
        feedback = self.store.list(rule.rule_id, rule.version)
        candidate = self.optimizer.optimize(
            rule,
            feedback,
            (record.event for record in records),
        )
        if target_event_ids is None:
            metadata = SigmaRuleValidator().parse(rule).metadata
            target_event_ids = set(metadata.get("event_ids", []))
        baseline = self.sandbox.replay(
            rule,
            records,
            dataset,
            target_event_ids,
        )
        candidate_validation = self.sandbox.replay(
            candidate,
            records,
            dataset,
            target_event_ids,
        )
        deltas = {
            "precision": (
                candidate_validation.result.precision
                - baseline.result.precision
            ),
            "recall": (
                candidate_validation.result.recall
                - baseline.result.recall
            ),
            "f1": candidate_validation.result.f1 - baseline.result.f1,
            "false_positive_rate": (
                candidate_validation.false_positive_rate
                - baseline.false_positive_rate
            ),
        }
        recommended = (
            candidate_validation.result.passed
            and deltas["f1"] > 0
            and deltas["false_positive_rate"] <= 0
        )
        rationale = self._rationale(feedback, deltas, recommended)
        return RuleEvolutionProposal(
            base_rule=rule,
            candidate_rule=candidate,
            baseline_validation=baseline,
            candidate_validation=candidate_validation,
            feedback_ids=[item.feedback_id for item in feedback],
            metric_deltas=deltas,
            recommended=recommended,
            rationale=rationale,
        )

    @staticmethod
    def _rationale(
        feedback: list[FeedbackRecord],
        deltas: dict[str, float],
        recommended: bool,
    ) -> list[str]:
        counts = {
            kind.value: sum(item.kind == kind for item in feedback)
            for kind in FeedbackKind
        }
        rationale = [
            f"Applied feedback counts: {counts}.",
            (
                f"Offline delta: precision={deltas['precision']:+.3f}, "
                f"recall={deltas['recall']:+.3f}, f1={deltas['f1']:+.3f}, "
                f"false_positive_rate={deltas['false_positive_rate']:+.3f}."
            ),
        ]
        rationale.append(
            "Candidate is recommended for a new approval cycle."
            if recommended
            else "Candidate is retained for review and is not approved automatically."
        )
        return rationale
