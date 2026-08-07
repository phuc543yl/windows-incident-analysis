"""Common correlation match contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from models.alert import Alert


@dataclass(frozen=True, slots=True)
class CorrelationMatch:
    incident_type: str
    title: str
    description: str
    alerts: tuple[Alert, ...]
    confidence_score: float
    recommendations: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.incident_type.strip() or not self.title.strip():
            raise ValueError(
                "incident_type và title không được để trống."
            )
        if not self.alerts:
            raise ValueError("CorrelationMatch cần ít nhất một Alert.")
        if not 0 <= self.confidence_score <= 1:
            raise ValueError(
                "confidence_score phải nằm trong khoảng 0-1."
            )
