"""Chronological event used to reconstruct an incident sequence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.time_utils import parse_timestamp
from models import (
    new_id,
    require_non_empty,
    string_tuple,
    to_json_value,
)


@dataclass(slots=True)
class TimelineEvent:
    case_id: str
    timestamp: datetime
    event_type: str
    summary: str
    timeline_event_id: str = field(default_factory=lambda: new_id("TL"))
    hostname: str = ""
    user: str = ""
    source_record_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    alert_ids: tuple[str, ...] = ()
    evidence_item_ids: tuple[str, ...] = ()
    sort_priority: int = 100
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.timestamp = parse_timestamp(self.timestamp)
        self.event_type = require_non_empty(self.event_type, "event_type")
        self.summary = require_non_empty(self.summary, "summary")
        self.timeline_event_id = require_non_empty(
            self.timeline_event_id,
            "timeline_event_id",
        )
        self.source_record_ids = string_tuple(self.source_record_ids)
        self.finding_ids = string_tuple(self.finding_ids)
        self.alert_ids = string_tuple(self.alert_ids)
        self.evidence_item_ids = string_tuple(self.evidence_item_ids)
        if isinstance(self.sort_priority, bool):
            raise TypeError("sort_priority phải là số nguyên.")
        self.sort_priority = int(self.sort_priority)
        self.details = dict(self.details)

    def sort_key(self) -> tuple[datetime, int, str]:
        return self.timestamp, self.sort_priority, self.timeline_event_id

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TimelineEvent":
        return cls(
            case_id=data["case_id"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            summary=data["summary"],
            timeline_event_id=data.get("timeline_event_id") or new_id("TL"),
            hostname=data.get("hostname", ""),
            user=data.get("user", ""),
            source_record_ids=tuple(data.get("source_record_ids", ())),
            finding_ids=tuple(data.get("finding_ids", ())),
            alert_ids=tuple(data.get("alert_ids", ())),
            evidence_item_ids=tuple(data.get("evidence_item_ids", ())),
            sort_priority=int(data.get("sort_priority", 100)),
            details=dict(data.get("details", {})),
        )
