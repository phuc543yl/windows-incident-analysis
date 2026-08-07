"""Correlated incident hypothesis and analyst-confirmed conclusion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.enums import CIAImpact, IncidentStatus
from common.time_utils import parse_timestamp, utc_now
from models import (
    enum_from_value,
    new_id,
    require_non_empty,
    string_tuple,
    to_json_value,
    validate_score,
)


@dataclass(slots=True)
class Incident:
    case_id: str
    title: str
    description: str
    incident_id: str = field(default_factory=lambda: new_id("INC"))
    status: IncidentStatus = IncidentStatus.SUSPECTED
    confidence_score: float = 0.5
    alert_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    timeline_event_ids: tuple[str, ...] = ()
    cia_impacts: tuple[CIAImpact, ...] = ()
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    analyst_conclusion: str = ""
    recommendations: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.title = require_non_empty(self.title, "title")
        self.description = require_non_empty(self.description, "description")
        self.incident_id = require_non_empty(self.incident_id, "incident_id")
        self.status = enum_from_value(
            IncidentStatus,
            self.status,
            "status",
        )
        self.confidence_score = validate_score(
            self.confidence_score,
            "confidence_score",
            1.0,
        )
        self.alert_ids = string_tuple(self.alert_ids)
        self.finding_ids = string_tuple(self.finding_ids)
        self.timeline_event_ids = string_tuple(self.timeline_event_ids)
        self.cia_impacts = tuple(
            enum_from_value(CIAImpact, impact, "cia_impact")
            for impact in self.cia_impacts
        )
        self.created_at = parse_timestamp(self.created_at)
        self.updated_at = parse_timestamp(self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("updated_at không được trước created_at.")
        self.recommendations = string_tuple(self.recommendations)
        self.details = dict(self.details)

    def set_status(
        self,
        status: IncidentStatus | str,
        *,
        conclusion: str = "",
        cia_impacts: tuple[CIAImpact | str, ...] | None = None,
        timestamp: datetime | str | None = None,
    ) -> None:
        self.status = enum_from_value(IncidentStatus, status, "status")
        if conclusion:
            self.analyst_conclusion = conclusion.strip()
        if cia_impacts is not None:
            self.cia_impacts = tuple(
                enum_from_value(CIAImpact, impact, "cia_impact")
                for impact in cia_impacts
            )
        updated_at = utc_now() if timestamp is None else parse_timestamp(timestamp)
        if updated_at < self.created_at:
            raise ValueError("updated_at không được trước created_at.")
        self.updated_at = updated_at

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        return cls(
            case_id=data["case_id"],
            title=data["title"],
            description=data["description"],
            incident_id=data.get("incident_id") or new_id("INC"),
            status=data.get("status", IncidentStatus.SUSPECTED.value),
            confidence_score=float(data.get("confidence_score", 0.5)),
            alert_ids=tuple(data.get("alert_ids", ())),
            finding_ids=tuple(data.get("finding_ids", ())),
            timeline_event_ids=tuple(data.get("timeline_event_ids", ())),
            cia_impacts=tuple(data.get("cia_impacts", ())),
            created_at=data.get("created_at") or utc_now(),
            updated_at=data.get("updated_at") or data.get("created_at") or utc_now(),
            analyst_conclusion=data.get("analyst_conclusion", ""),
            recommendations=tuple(data.get("recommendations", ())),
            details=dict(data.get("details", {})),
        )
