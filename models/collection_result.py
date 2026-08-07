"""Result returned by one collector execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.enums import CollectionStatus
from common.time_utils import parse_timestamp, utc_now
from models import (
    enum_from_value,
    new_id,
    optional_timestamp,
    require_non_empty,
    string_tuple,
    to_json_value,
)


@dataclass(slots=True)
class CollectionResult:
    case_id: str
    plan_id: str
    collector_id: str
    status: CollectionStatus
    result_id: str = field(default_factory=lambda: new_id("COLLECT"))
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    record_count: int = 0
    evidence_item_ids: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.plan_id = require_non_empty(self.plan_id, "plan_id")
        self.collector_id = require_non_empty(
            self.collector_id,
            "collector_id",
        )
        self.result_id = require_non_empty(self.result_id, "result_id")
        self.status = enum_from_value(CollectionStatus, self.status, "status")
        self.started_at = parse_timestamp(self.started_at)
        self.finished_at = optional_timestamp(self.finished_at)
        if isinstance(self.record_count, bool) or not isinstance(
            self.record_count,
            int,
        ):
            raise TypeError("record_count phải là số nguyên.")
        if self.record_count < 0:
            raise ValueError("record_count phải là số nguyên không âm.")
        self.evidence_item_ids = string_tuple(self.evidence_item_ids)
        self.warnings = string_tuple(self.warnings)
        self.errors = string_tuple(self.errors)
        self.metadata = dict(self.metadata)
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("finished_at không được trước started_at.")

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def succeeded(self) -> bool:
        return self.status in {
            CollectionStatus.SUCCEEDED,
            CollectionStatus.PARTIAL,
        }

    def finish(
        self,
        status: CollectionStatus | str,
        *,
        timestamp: datetime | str | None = None,
    ) -> None:
        finished_at = utc_now() if timestamp is None else parse_timestamp(timestamp)
        if finished_at < self.started_at:
            raise ValueError("finished_at không được trước started_at.")
        self.status = enum_from_value(CollectionStatus, status, "status")
        self.finished_at = finished_at

    def to_dict(self) -> dict[str, Any]:
        data = to_json_value(self)
        data["duration_seconds"] = self.duration_seconds
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CollectionResult":
        return cls(
            case_id=data["case_id"],
            plan_id=data["plan_id"],
            collector_id=data["collector_id"],
            status=data["status"],
            result_id=data.get("result_id") or new_id("COLLECT"),
            started_at=data.get("started_at") or utc_now(),
            finished_at=data.get("finished_at"),
            record_count=int(data.get("record_count", 0)),
            evidence_item_ids=tuple(data.get("evidence_item_ids", ())),
            warnings=tuple(data.get("warnings", ())),
            errors=tuple(data.get("errors", ())),
            metadata=dict(data.get("metadata", {})),
        )
