"""Detection Alert produced when a configured rule condition is met."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from common.enums import FindingSeverity
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
class Alert:
    case_id: str
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    risk_score: float
    alert_id: str = field(default_factory=lambda: new_id("ALERT"))
    status: str = "open"
    finding_ids: tuple[str, ...] = ()
    source_record_ids: tuple[str, ...] = ()
    evidence_item_ids: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utc_now)
    recommendation: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    ALLOWED_STATUSES: ClassVar[set[str]] = {
        "open",
        "acknowledged",
        "dismissed",
        "closed",
    }

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.rule_id = require_non_empty(self.rule_id, "rule_id")
        self.title = require_non_empty(self.title, "title")
        self.description = require_non_empty(self.description, "description")
        self.alert_id = require_non_empty(self.alert_id, "alert_id")
        self.severity = enum_from_value(
            FindingSeverity,
            self.severity,
            "severity",
        )
        self.risk_score = validate_score(
            self.risk_score,
            "risk_score",
            100.0,
        )
        self.status = require_non_empty(self.status, "status").lower()
        if self.status not in self.ALLOWED_STATUSES:
            raise ValueError(f"Alert status không hợp lệ: {self.status}")
        self.finding_ids = string_tuple(self.finding_ids)
        self.source_record_ids = string_tuple(self.source_record_ids)
        self.evidence_item_ids = string_tuple(self.evidence_item_ids)
        self.mitre_techniques = string_tuple(self.mitre_techniques)
        self.created_at = parse_timestamp(self.created_at)
        self.details = dict(self.details)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        return cls(
            case_id=data["case_id"],
            rule_id=data["rule_id"],
            title=data["title"],
            description=data["description"],
            severity=data["severity"],
            risk_score=float(data["risk_score"]),
            alert_id=data.get("alert_id") or new_id("ALERT"),
            status=data.get("status", "open"),
            finding_ids=tuple(data.get("finding_ids", ())),
            source_record_ids=tuple(data.get("source_record_ids", ())),
            evidence_item_ids=tuple(data.get("evidence_item_ids", ())),
            mitre_techniques=tuple(data.get("mitre_techniques", ())),
            created_at=data.get("created_at") or utc_now(),
            recommendation=data.get("recommendation", ""),
            details=dict(data.get("details", {})),
        )
