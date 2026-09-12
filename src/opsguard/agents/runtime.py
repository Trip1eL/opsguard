"""Adapters that expose the deterministic M2-M5 services as agent tools."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from opsguard.attack import AttackTechniqueMapper
from opsguard.correlation import BehaviorCorrelator
from opsguard.data.fixtures import DatasetRecord
from opsguard.detection import DetectionEngine
from opsguard.domain.cases import Alert
from opsguard.domain.models import BehaviorChain, DetectionRule, Event
from opsguard.governance import (
    ApprovalDecision,
    CanaryMetrics,
    GovernanceCoordinator,
)
from opsguard.repositories import EventQuery, EventRepository
from opsguard.rules import (
    OfflineRuleSandbox,
    RuleValidationReport,
    SigmaRuleGenerator,
)

from .tools import EmptyToolResultError, ToolRegistry, ToolSpec

QUERY_FIELDS = {
    "start_time",
    "end_time",
    "event_ids",
    "source",
    "host",
    "user",
    "process",
    "src_ip",
    "dst_ip",
    "domain",
    "action",
}


class InvestigationToolbox:
    """Provide typed, side-effect-free handlers for one investigation runtime."""

    def __init__(
        self,
        repository: EventRepository,
        attack_mapper: AttackTechniqueMapper,
        detection_engine: DetectionEngine | None = None,
        correlator: BehaviorCorrelator | None = None,
        validation_records: Iterable[DatasetRecord] = (),
        rule_generator: SigmaRuleGenerator | None = None,
        rule_sandbox: OfflineRuleSandbox | None = None,
        validation_dataset: str = "opsguard-fixtures",
        governance: GovernanceCoordinator | None = None,
    ) -> None:
        self.repository = repository
        self.attack_mapper = attack_mapper
        self.detection_engine = detection_engine or DetectionEngine()
        self.correlator = correlator or BehaviorCorrelator()
        self.validation_records = list(validation_records)
        self.rule_generator = rule_generator or SigmaRuleGenerator()
        self.rule_sandbox = rule_sandbox or OfflineRuleSandbox()
        self.validation_dataset = validation_dataset
        self.governance = governance or GovernanceCoordinator()

    def registry(self) -> ToolRegistry:
        return ToolRegistry(
            [
                ToolSpec(
                    "search_events",
                    "Search normalized security events with structured filters.",
                    self.search_events,
                    _validate_list_output,
                ),
                ToolSpec(
                    "govern_policy_and_response",
                    "Assess risk and enforce approval, canary, and response controls.",
                    self.govern_policy_and_response,
                    _validate_list_output,
                ),
                ToolSpec(
                    "detect_anomalies",
                    "Run deterministic anomaly detectors over retrieved events.",
                    self.detect_anomalies,
                    _validate_list_output,
                ),
                ToolSpec(
                    "correlate_behavior",
                    "Build evidence-backed behavior chains and entity graphs.",
                    self.correlate_behavior,
                    _validate_list_output,
                ),
                ToolSpec(
                    "map_attack_techniques",
                    "Map behavior evidence to the local versioned ATT&CK catalog.",
                    self.map_attack_techniques,
                    _validate_list_output,
                ),
                ToolSpec(
                    "get_detection_coverage",
                    "Measure requested ATT&CK technique coverage for each chain.",
                    self.get_detection_coverage,
                    _validate_list_output,
                ),
                ToolSpec(
                    "generate_detection_rules",
                    "Generate versioned Sigma candidates from mapped behavior.",
                    self.generate_detection_rules,
                    _validate_list_output,
                ),
                ToolSpec(
                    "validate_detection_rules",
                    "Replay Sigma candidates in the isolated fixture sandbox.",
                    self.validate_detection_rules,
                    _validate_list_output,
                ),
            ]
        )

    def search_events(self, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        filters = {key: payload[key] for key in QUERY_FIELDS if key in payload}
        query = EventQuery.model_validate(filters)
        events = self.repository.search(query)
        if not events:
            raise EmptyToolResultError("no events matched the investigation query")
        return [event.model_dump(mode="json") for event in events]

    def detect_anomalies(self, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        events = self._events(payload)
        alerts = self.detection_engine.detect(events)
        alerts = self._select_relevant_alerts(str(payload["question"]), alerts)
        if not alerts:
            raise EmptyToolResultError("no anomalous behavior was detected")
        return [alert.model_dump(mode="json") for alert in alerts]

    def correlate_behavior(self, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        events = self._events(payload)
        alerts = [Alert.model_validate(item) for item in payload.get("alerts", [])]
        if not alerts:
            raise EmptyToolResultError("correlation requires at least one alert")

        results = []
        for alert in alerts:
            result = self.correlator.correlate(alert, events)
            results.append(
                {
                    "alert_id": alert.alert_id,
                    "chain": result.chain.model_dump(mode="json"),
                    "graph": result.graph.model_dump(mode="json"),
                }
            )
        return results

    def map_attack_techniques(
        self,
        payload: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        events = self._events(payload)
        behavior_chains = payload.get("behavior_chains", [])
        results = []
        for item in behavior_chains:
            chain = BehaviorChain.model_validate(item["chain"])
            mapped = self.attack_mapper.map_chain(chain, events)
            results.append(
                {
                    "alert_id": item["alert_id"],
                    "chain": mapped.model_dump(mode="json"),
                }
            )
        if not results:
            raise EmptyToolResultError("ATT&CK mapping requires a behavior chain")
        return results

    def get_detection_coverage(
        self,
        payload: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        requested = payload.get("requested_technique_ids")
        results = []
        for item in payload.get("attack_mappings", []):
            chain = BehaviorChain.model_validate(item["chain"])
            coverage = self.attack_mapper.coverage(chain, requested)
            results.append(coverage.model_dump(mode="json"))
        if not results:
            raise EmptyToolResultError("coverage requires ATT&CK mapping results")
        return results

    def generate_detection_rules(
        self,
        payload: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        version = int(payload.get("rule_version", 1))
        results = []
        for item in payload.get("attack_mappings", []):
            chain = BehaviorChain.model_validate(item["chain"])
            rule = self.rule_generator.generate(chain, version)
            results.append(
                {
                    "chain_id": chain.case_id,
                    "event_ids": chain.event_ids,
                    "rule": rule.model_dump(mode="json"),
                }
            )
        if not results:
            raise EmptyToolResultError("rule generation requires ATT&CK mappings")
        return results

    def validate_detection_rules(
        self,
        payload: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        if not self.validation_records:
            raise EmptyToolResultError("no labeled records are available for validation")
        results = []
        for item in payload.get("candidate_rules", []):
            rule = DetectionRule.model_validate(item["rule"])
            report = self.rule_sandbox.replay(
                rule,
                self.validation_records,
                self.validation_dataset,
                set(item["event_ids"]),
            )
            result = report.model_dump(mode="json")
            result.update(
                {
                    "chain_id": item["chain_id"],
                    "event_ids": item["event_ids"],
                }
            )
            results.append(result)
        if not results:
            raise EmptyToolResultError("validation requires candidate rules")
        return results

    def govern_policy_and_response(
        self,
        payload: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        events = self._events(payload)
        alerts = [Alert.model_validate(item) for item in payload.get("alerts", [])]
        mappings = {
            item["chain"]["case_id"]: item
            for item in payload.get("attack_mappings", [])
        }
        results = []
        for item in payload.get("rule_validations", []):
            chain_id = item["chain_id"]
            mapping = mappings[chain_id]
            chain = BehaviorChain.model_validate(mapping["chain"])
            chain_alerts = [
                alert for alert in alerts if alert.alert_id == mapping["alert_id"]
            ]
            approval_payload = self._scoped_parameter(
                payload.get("approvals", payload.get("approval")),
                chain_id,
            )
            metrics_payload = self._scoped_parameter(
                payload.get("canary_metrics"),
                chain_id,
            )
            outcome = self.governance.govern(
                chain_alerts,
                chain,
                events,
                RuleValidationReport.model_validate(item),
                (
                    ApprovalDecision.model_validate(approval_payload)
                    if approval_payload
                    else None
                ),
                (
                    CanaryMetrics.model_validate(metrics_payload)
                    if metrics_payload
                    else None
                ),
            )
            results.append(outcome.model_dump(mode="json"))
        if not results:
            raise EmptyToolResultError("governance requires validation results")
        return results

    @staticmethod
    def _scoped_parameter(value: Any, scope_id: str) -> Any:
        if isinstance(value, list):
            return next(
                (item for item in value if item.get("scope_id") == scope_id),
                None,
            )
        if isinstance(value, dict) and scope_id in value:
            return value[scope_id]
        return value

    @staticmethod
    def _events(payload: Mapping[str, Any]) -> list[Event]:
        events = [Event.model_validate(item) for item in payload.get("events", [])]
        if not events:
            raise EmptyToolResultError("tool input contains no events")
        return events

    @staticmethod
    def _select_relevant_alerts(question: str, alerts: list[Alert]) -> list[Alert]:
        normalized = question.casefold()
        prefixes: set[str] = set()
        if "ssh" in normalized or "登录" in normalized:
            prefixes.add("alert-suspicious_login")
        if any(term in normalized for term in ("web", "网页", "网站", "子进程")):
            prefixes.add("alert-web_child_process")
        if any(term in normalized for term in ("cron", "计划任务", "定时任务")):
            prefixes.add("alert-scheduled_task_persistence")
        if not prefixes:
            return alerts
        selected = [
            alert
            for alert in alerts
            if any(alert.alert_id.startswith(prefix) for prefix in prefixes)
        ]
        return selected


def _validate_list_output(output: Any) -> list[dict[str, Any]]:
    if not isinstance(output, list):
        raise TypeError("expected a list")
    if not all(isinstance(item, dict) for item in output):
        raise TypeError("expected a list of objects")
    return output
