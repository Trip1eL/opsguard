"""Deterministic, explainable risk grading for investigation outcomes."""

from __future__ import annotations

from collections.abc import Sequence

from opsguard.domain.cases import Alert
from opsguard.domain.models import BehaviorChain

from .models import RiskAssessment, RiskLevel


class RiskAssessor:
    def assess(
        self,
        scope_id: str,
        alerts: Sequence[Alert],
        chain: BehaviorChain,
    ) -> RiskAssessment:
        if not alerts:
            raise ValueError("risk assessment requires at least one alert")

        base_score = max(alert.risk_score for alert in alerts)
        technique_ids = {mapping.technique_id for mapping in chain.mappings}
        score = base_score
        factors = [f"maximum alert risk score={base_score:.2f}"]
        if "T1505.003" in technique_ids:
            score += 0.05
            factors.append("web server spawned a command interpreter")
        if "T1053.003" in technique_ids:
            score += 0.03
            factors.append("scheduled-task persistence was observed")
        if len(chain.stages) >= 3:
            score += 0.02
            factors.append("behavior spans at least three attack stages")
        score = min(score, 1.0)
        level = self._level(score)
        return RiskAssessment(
            scope_id=scope_id,
            score=score,
            level=level,
            requires_human_approval=level in {
                RiskLevel.MEDIUM,
                RiskLevel.HIGH,
                RiskLevel.CRITICAL,
            },
            factors=factors,
        )

    @staticmethod
    def _level(score: float) -> RiskLevel:
        if score >= 0.95:
            return RiskLevel.CRITICAL
        if score >= 0.75:
            return RiskLevel.HIGH
        if score >= 0.50:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
