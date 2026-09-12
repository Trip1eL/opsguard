from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, Field

from opsguard.domain.models import BehaviorChain, Event, Evidence, TechniqueMapping


class TechniqueDefinition(BaseModel):
    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    description: str


class TechniqueCatalog(BaseModel):
    version: str
    source: str
    techniques: list[TechniqueDefinition]

    @classmethod
    def from_json(cls, path: Path) -> TechniqueCatalog:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def get(self, technique_id: str) -> TechniqueDefinition:
        for technique in self.techniques:
            if technique.technique_id == technique_id:
                return technique
        raise KeyError(f"unknown ATT&CK technique: {technique_id}")


class CoverageReport(BaseModel):
    chain_id: str
    mapped_technique_ids: list[str] = Field(default_factory=list)
    requested_technique_ids: list[str] = Field(default_factory=list)
    uncovered_technique_ids: list[str] = Field(default_factory=list)
    coverage_ratio: float = Field(ge=0, le=1)


class AttackTechniqueMapper:
    """Map behavior evidence to a versioned local ATT&CK subset."""

    def __init__(self, catalog: TechniqueCatalog) -> None:
        self.catalog = catalog

    def map_chain(self, chain: BehaviorChain, events: Iterable[Event]) -> BehaviorChain:
        event_index = {event.event_id: event for event in events}
        chain_events = [
            event_index[event_id]
            for event_id in chain.event_ids
            if event_id in event_index
        ]
        return chain.model_copy(update={"mappings": self.map_events(chain_events)})

    def map_events(self, events: Iterable[Event]) -> list[TechniqueMapping]:
        grouped: dict[str, list[Evidence]] = {}
        for event in events:
            for technique_id, summary, confidence in self._matches(event):
                grouped.setdefault(technique_id, []).append(
                    Evidence(
                        event_ids=[event.event_id],
                        summary=summary,
                        confidence=confidence,
                    )
                )

        mappings: list[TechniqueMapping] = []
        for technique_id in sorted(grouped):
            definition = self.catalog.get(technique_id)
            evidence = grouped[technique_id]
            mappings.append(
                TechniqueMapping(
                    technique_id=technique_id,
                    name=definition.name,
                    evidence=evidence,
                    confidence=min(item.confidence for item in evidence),
                )
            )
        return mappings

    def coverage(
        self,
        chain: BehaviorChain,
        requested_technique_ids: Iterable[str] | None = None,
    ) -> CoverageReport:
        requested = sorted(
            set(requested_technique_ids or [item.technique_id for item in chain.mappings])
        )
        all_mapped = {item.technique_id for item in chain.mappings}
        mapped = sorted(all_mapped & set(requested))
        uncovered = sorted(set(requested) - all_mapped)
        ratio = len(mapped) / len(requested) if requested else 1.0
        return CoverageReport(
            chain_id=chain.case_id,
            mapped_technique_ids=mapped,
            requested_technique_ids=requested,
            uncovered_technique_ids=uncovered,
            coverage_ratio=ratio,
        )

    def _matches(self, event: Event) -> list[tuple[str, str, float]]:
        matches: list[tuple[str, str, float]] = []
        if event.action == "ssh_login" and (
            event.attributes.get("auth_method") == "password"
            or event.attributes.get("new_source") is True
        ):
            matches.append(("T1021.004", "Suspicious SSH login observed", 0.97))
        if event.action == "scheduled_task_create":
            matches.append(("T1053.003", "Cron or scheduled task creation observed", 0.98))
        if event.process in {"bash", "sh", "zsh", "powershell", "cmd", "python", "python3"}:
            matches.append(("T1059.004", f"Unix shell-like process started: {event.process}", 0.86))
        if event.process in {"curl", "wget"} and event.domain:
            matches.append(("T1105", f"Downloader accessed {event.domain}", 0.91))
        if event.parent_process in {"nginx", "apache2", "httpd", "gunicorn"} and event.process in {
            "bash", "sh", "zsh", "powershell", "cmd", "python", "python3"
        }:
            matches.append(("T1505.003", "Web server spawned a command interpreter", 0.88))
        if event.action == "network_connect" and event.attributes.get("dst_port") in {80, 443}:
            matches.append(("T1071.001", "HTTP or HTTPS network connection observed", 0.82))
        return matches

