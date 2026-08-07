"""Case model for one isolated Windows incident investigation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from common.enums import CaseStatus, OperationMode
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
class Case:
    case_id: str
    title: str
    target_host_id: str
    profile_id: str
    mode: OperationMode = OperationMode.LOCAL
    description: str = ""
    hypothesis: str = ""
    status: CaseStatus = CaseStatus.OPEN
    created_by: str = ""
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    closed_at: datetime | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    CASE_ID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^CASE-\d{8}-\d{3,6}$"
    )

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id").upper()
        if not self.CASE_ID_PATTERN.fullmatch(self.case_id):
            raise ValueError(
                "case_id phải có dạng CASE-YYYYMMDD-NNN, "
                "ví dụ CASE-20260729-001."
            )
        self.title = require_non_empty(self.title, "title")
        self.target_host_id = require_non_empty(
            self.target_host_id,
            "target_host_id",
        )
        self.profile_id = require_non_empty(self.profile_id, "profile_id")
        self.mode = enum_from_value(OperationMode, self.mode, "mode")
        self.status = enum_from_value(CaseStatus, self.status, "status")
        self.created_at = parse_timestamp(self.created_at)
        self.updated_at = parse_timestamp(self.updated_at)
        self.closed_at = optional_timestamp(self.closed_at)
        self.tags = string_tuple(self.tags)
        self.metadata = dict(self.metadata)
        if self.updated_at < self.created_at:
            raise ValueError("updated_at không được trước created_at.")
        if self.status is CaseStatus.CLOSED and self.closed_at is None:
            raise ValueError("Case đã đóng phải có closed_at.")

    def touch(self, timestamp: datetime | str | None = None) -> None:
        candidate = utc_now() if timestamp is None else parse_timestamp(timestamp)
        if candidate < self.created_at:
            raise ValueError("updated_at không được trước created_at.")
        self.updated_at = candidate

    def close(self, timestamp: datetime | str | None = None) -> None:
        closed_at = utc_now() if timestamp is None else parse_timestamp(timestamp)
        if closed_at < self.created_at:
            raise ValueError("closed_at không được trước created_at.")
        self.status = CaseStatus.CLOSED
        self.closed_at = closed_at
        self.updated_at = closed_at

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Case":
        return cls(
            case_id=data["case_id"],
            title=data["title"],
            target_host_id=data["target_host_id"],
            profile_id=data["profile_id"],
            mode=data.get("mode", OperationMode.LOCAL.value),
            description=data.get("description", ""),
            hypothesis=data.get("hypothesis", ""),
            status=data.get("status", CaseStatus.OPEN.value),
            created_by=data.get("created_by", ""),
            created_at=data.get("created_at") or utc_now(),
            updated_at=data.get("updated_at") or data.get("created_at") or utc_now(),
            closed_at=data.get("closed_at"),
            tags=tuple(data.get("tags", ())),
            metadata=dict(data.get("metadata", {})),
        )
