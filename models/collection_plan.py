"""Collection Plan shared by Local Mode and Agent Mode."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.constants import (
    SUPPORTED_ARTIFACT_COLLECTORS,
    SUPPORTED_LIVE_COLLECTORS,
)
from common.enums import OperationMode
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
class CollectionPlan:
    case_id: str
    profile_id: str
    mode: OperationMode
    live_collectors: tuple[str, ...]
    artifact_collectors: tuple[str, ...]
    plan_id: str = field(default_factory=lambda: new_id("PLAN"))
    created_at: datetime = field(default_factory=utc_now)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    target_agent_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.profile_id = require_non_empty(self.profile_id, "profile_id")
        self.plan_id = require_non_empty(self.plan_id, "plan_id")
        self.mode = enum_from_value(OperationMode, self.mode, "mode")
        self.live_collectors = string_tuple(self.live_collectors)
        self.artifact_collectors = string_tuple(self.artifact_collectors)
        self.created_at = parse_timestamp(self.created_at)
        self.time_range_start = optional_timestamp(self.time_range_start)
        self.time_range_end = optional_timestamp(self.time_range_end)
        self.options = dict(self.options)

        unknown_live = set(self.live_collectors) - set(SUPPORTED_LIVE_COLLECTORS)
        unknown_artifacts = set(self.artifact_collectors) - set(
            SUPPORTED_ARTIFACT_COLLECTORS
        )
        if unknown_live:
            raise ValueError(
                f"Live collector không được hỗ trợ: {sorted(unknown_live)}"
            )
        if unknown_artifacts:
            raise ValueError(
                "Artifact collector không được hỗ trợ: "
                f"{sorted(unknown_artifacts)}"
            )
        if (self.time_range_start is None) != (self.time_range_end is None):
            raise ValueError(
                "time_range_start và time_range_end phải cùng được khai báo."
            )
        if (
            self.time_range_start is not None
            and self.time_range_end is not None
            and self.time_range_start > self.time_range_end
        ):
            raise ValueError("Khoảng thời gian thu thập không hợp lệ.")
        if self.mode is OperationMode.AGENT:
            self.target_agent_id = require_non_empty(
                self.target_agent_id,
                "target_agent_id",
            )
        elif self.target_agent_id is not None:
            self.target_agent_id = require_non_empty(
                self.target_agent_id,
                "target_agent_id",
            )

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CollectionPlan":
        return cls(
            case_id=data["case_id"],
            profile_id=data["profile_id"],
            mode=data["mode"],
            live_collectors=tuple(data.get("live_collectors", ())),
            artifact_collectors=tuple(data.get("artifact_collectors", ())),
            plan_id=data.get("plan_id") or new_id("PLAN"),
            created_at=data.get("created_at") or utc_now(),
            time_range_start=data.get("time_range_start"),
            time_range_end=data.get("time_range_end"),
            target_agent_id=data.get("target_agent_id"),
            options=dict(data.get("options", {})),
        )
