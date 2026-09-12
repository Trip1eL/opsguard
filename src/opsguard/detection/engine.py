from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import ClassVar, Protocol

from opsguard.domain.cases import Alert, AlertSeverity
from opsguard.domain.models import Event, Evidence

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class DetectionRuleEvaluator(Protocol):
    rule_id: str

    def evaluate(self, event: Event) -> Alert | None: ...


def _severity_for(score: float) -> AlertSeverity:
    if score >= 0.85:
        return AlertSeverity.HIGH
    if score >= 0.65:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


def _alert(
    rule_id: str,
    event: Event,
    title: str,
    score: float,
    summary: str,
    confidence: float = 0.9,
) -> Alert:
    return Alert(
        alert_id=f"alert-{rule_id}-{event.event_id}",
        title=title,
        severity=_severity_for(score),
        event_ids=[event.event_id],
        evidence=[
            Evidence(
                event_ids=[event.event_id],
                summary=summary,
                confidence=confidence,
            )
        ],
        risk_score=score,
    )


class SuspiciousLoginRule:
    rule_id = "suspicious_login"

    def evaluate(self, event: Event) -> Alert | None:
        if event.action != "ssh_login":
            return None
        if event.attributes.get("success") is not True:
            return None
        if event.attributes.get("auth_method") != "password":
            return None
        if event.attributes.get("new_source") is not True:
            return None
        return _alert(
            self.rule_id,
            event,
            "Successful SSH login from a new source",
            0.80,
            f"user={event.user} logged in from new source {event.src_ip}",
        )


class ScheduledTaskPersistenceRule:
    rule_id = "scheduled_task_persistence"

    def evaluate(self, event: Event) -> Alert | None:
        if event.action != "scheduled_task_create":
            return None
        command = str(event.attributes.get("command", ""))
        suspicious_path = "/tmp/" in command or "/var/tmp/" in command
        score = 0.95 if suspicious_path else 0.86
        return _alert(
            self.rule_id,
            event,
            "Scheduled task executes a suspicious command",
            score,
            f"scheduled task created by {event.user} with command={command}",
        )


class WebChildProcessRule:
    rule_id = "web_child_process"
    web_processes: ClassVar[frozenset[str]] = frozenset(
        {"nginx", "apache2", "httpd", "gunicorn"}
    )
    shell_processes: ClassVar[frozenset[str]] = frozenset(
        {"bash", "sh", "zsh", "powershell", "cmd", "python", "python3"}
    )

    def evaluate(self, event: Event) -> Alert | None:
        if event.action != "process_start":
            return None
        if event.parent_process not in self.web_processes:
            return None
        if event.process not in self.shell_processes:
            return None
        return _alert(
            self.rule_id,
            event,
            "Web process spawned an interpreter",
            0.90,
            f"parent={event.parent_process} spawned process={event.process} file={event.file}",
        )


class InterpreterExecutionRule:
    rule_id = "interpreter_execution"
    interpreter_processes: ClassVar[frozenset[str]] = frozenset(
        {"bash", "sh", "zsh", "powershell", "cmd", "python", "python3", "curl", "wget"}
    )

    def evaluate(self, event: Event) -> Alert | None:
        if event.action != "process_start" or event.process not in self.interpreter_processes:
            return None
        command = str(event.attributes.get("command", ""))
        if not command and not event.file and not event.domain:
            return None
        if event.parent_process in WebChildProcessRule.web_processes:
            return None
        score = 0.76 if event.process in {"bash", "sh", "powershell"} else 0.68
        return _alert(
            self.rule_id,
            event,
            "Interpreter or downloader executed a non-standard command",
            score,
            f"process={event.process} parent={event.parent_process} command={command}",
        )


class ExternalNetworkConnectionRule:
    rule_id = "external_network_connection"

    def evaluate(self, event: Event) -> Alert | None:
        if event.action != "network_connect" or not event.dst_ip:
            return None
        try:
            address = ipaddress.ip_address(event.dst_ip)
        except ValueError:
            return None
        if (
            any(address in network for network in RFC1918_NETWORKS)
            or address.is_loopback
            or address.is_link_local
        ):
            return None
        return _alert(
            self.rule_id,
            event,
            "Process connected to an external network destination",
            0.68,
            f"process={event.process} connected to {event.domain or event.dst_ip}",
        )


@dataclass(frozen=True)
class DetectionEngine:
    rules: Sequence[DetectionRuleEvaluator] = (
        SuspiciousLoginRule(),
        ScheduledTaskPersistenceRule(),
        WebChildProcessRule(),
        InterpreterExecutionRule(),
        ExternalNetworkConnectionRule(),
    )

    def detect(self, events: Iterable[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
            for rule in self.rules:
                alert = rule.evaluate(event)
                if alert is not None:
                    alerts.append(alert)
        return alerts

