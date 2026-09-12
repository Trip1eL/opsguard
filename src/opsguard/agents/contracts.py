from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from opsguard.domain.models import (
    BehaviorChain,
    DetectionRule,
    Event,
    TechniqueMapping,
    ValidationResult,
)


class EventInvestigator(Protocol):
    def investigate(self, question: str, events: Sequence[Event]) -> list[Event]: ...


class BehaviorCorrelator(Protocol):
    def correlate(self, case_id: str, events: Sequence[Event]) -> BehaviorChain: ...


class TechniqueMapper(Protocol):
    def map(self, chain: BehaviorChain) -> list[TechniqueMapping]: ...


class DetectionEngineer(Protocol):
    def generate(self, chain: BehaviorChain) -> DetectionRule: ...


class RuleValidator(Protocol):
    def validate(self, rule: DetectionRule, dataset: str) -> ValidationResult: ...
