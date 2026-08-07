"""Noteworthy observation produced by a parser or analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

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
class Finding:
    case_id: str
    title: str
    description: str
    severity: FindingSeverity
    finding_id: str = field(default_factory=lambda: new_id("FIND"))
    analyzer_id: str = ""
    rule_id: str | None = None
    source_record_ids: tuple[str, ...] = ()
    evidence_item_ids: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    confidence_score: float = 0.5
    created_at: datetime = field(default_factory=utc_now)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.title = require_non_empty(self.title, "title")
        self.description = require_non_empty(self.description, "description")
        self.finding_id = require_non_empty(self.finding_id, "finding_id")
        self.severity = enum_from_value(
            FindingSeverity,
            self.severity,
            "severity",
        )
        if self.rule_id is not None:
            self.rule_id = require_non_empty(self.rule_id, "rule_id")
        self.source_record_ids = string_tuple(self.source_record_ids)
        self.evidence_item_ids = string_tuple(self.evidence_item_ids)
        self.mitre_techniques = string_tuple(self.mitre_techniques)
        self.confidence_score = validate_score(
            self.confidence_score,
            "confidence_score",
            1.0,
        )
        self.created_at = parse_timestamp(self.created_at)
        self.details = dict(self.details)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(
            case_id=data["case_id"],
            title=data["title"],
            description=data["description"],
            severity=data["severity"],
            finding_id=data.get("finding_id") or new_id("FIND"),
            analyzer_id=data.get("analyzer_id", ""),
            rule_id=data.get("rule_id"),
            source_record_ids=tuple(data.get("source_record_ids", ())),
            evidence_item_ids=tuple(data.get("evidence_item_ids", ())),
            mitre_techniques=tuple(data.get("mitre_techniques", ())),
            confidence_score=float(data.get("confidence_score", 0.5)),
            created_at=data.get("created_at") or utc_now(),
            details=dict(data.get("details", {})),
        )
