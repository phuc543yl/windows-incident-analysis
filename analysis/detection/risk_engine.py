"""Consistent, bounded risk scoring for detection Alerts."""

from __future__ import annotations

from common.enums import FindingSeverity

_SEVERITY_FLOORS = {
    FindingSeverity.INFO: 0.0,
    FindingSeverity.LOW: 20.0,
    FindingSeverity.MEDIUM: 40.0,
    FindingSeverity.HIGH: 60.0,
    FindingSeverity.CRITICAL: 85.0,
}


class RiskEngine:
    def calculate(
        self,
        base_score: int | float,
        severity: FindingSeverity | str,
        *,
        record_count: int = 1,
        indicator_hits: int = 0,
    ) -> float:
        normalized_severity = (
            severity
            if isinstance(severity, FindingSeverity)
            else FindingSeverity(str(severity))
        )
        if isinstance(base_score, bool):
            raise TypeError("base_score phải là số.")
        score = float(base_score)
        if not 0 <= score <= 100:
            raise ValueError("base_score phải nằm trong khoảng 0-100.")
        if record_count < 1 or indicator_hits < 0:
            raise ValueError(
                "record_count phải dương và indicator_hits không được âm."
            )
        score = max(score, _SEVERITY_FLOORS[normalized_severity])
        score += min(10.0, max(0, record_count - 1) * 2.0)
        score += min(5.0, indicator_hits * 1.5)
        return round(min(100.0, score), 2)
