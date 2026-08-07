"""Result of executing an integrated DFIR tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.enums import ToolRunStatus
from common.time_utils import parse_timestamp, utc_now
from models import (
    enum_from_value,
    new_id,
    optional_timestamp,
    portable_path,
    require_non_empty,
    string_tuple,
    to_json_value,
)


@dataclass(slots=True)
class ToolResult:
    case_id: str
    tool_id: str
    status: ToolRunStatus
    tool_result_id: str = field(default_factory=lambda: new_id("TOOL"))
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    exit_code: int | None = None
    command: tuple[str, ...] = ()
    output_files: tuple[str, ...] = ()
    stdout_path: str | None = None
    stderr_path: str | None = None
    error_message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.tool_id = require_non_empty(self.tool_id, "tool_id")
        self.tool_result_id = require_non_empty(
            self.tool_result_id,
            "tool_result_id",
        )
        self.status = enum_from_value(ToolRunStatus, self.status, "status")
        self.started_at = parse_timestamp(self.started_at)
        self.finished_at = optional_timestamp(self.finished_at)
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("finished_at không được trước started_at.")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool)
            or not isinstance(self.exit_code, int)
        ):
            raise TypeError("exit_code phải là số nguyên hoặc None.")
        self.command = tuple(
            require_non_empty(str(item), "command item")
            for item in self.command
        )
        self.output_files = tuple(
            portable_path(path, "output_file")
            for path in string_tuple(self.output_files)
        )
        if self.stdout_path is not None:
            self.stdout_path = portable_path(self.stdout_path, "stdout_path")
        if self.stderr_path is not None:
            self.stderr_path = portable_path(self.stderr_path, "stderr_path")
        self.metadata = dict(self.metadata)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        data = to_json_value(self)
        data["duration_seconds"] = self.duration_seconds
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolResult":
        return cls(
            case_id=data["case_id"],
            tool_id=data["tool_id"],
            status=data["status"],
            tool_result_id=data.get("tool_result_id") or new_id("TOOL"),
            started_at=data.get("started_at") or utc_now(),
            finished_at=data.get("finished_at"),
            exit_code=data.get("exit_code"),
            command=tuple(data.get("command", ())),
            output_files=tuple(data.get("output_files", ())),
            stdout_path=data.get("stdout_path"),
            stderr_path=data.get("stderr_path"),
            error_message=data.get("error_message", ""),
            metadata=dict(data.get("metadata", {})),
        )
