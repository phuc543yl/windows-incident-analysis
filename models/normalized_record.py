"""Common schema for records produced by collectors and DFIR parsers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from common.enums import ArtifactType
from common.time_utils import parse_timestamp
from models import (
    enum_from_value,
    new_id,
    portable_path,
    require_non_empty,
    to_json_value,
)


@dataclass(slots=True)
class NormalizedRecord:
    case_id: str
    source_type: str
    artifact_type: ArtifactType
    timestamp: datetime
    summary: str
    record_id: str = field(default_factory=lambda: new_id("REC"))
    hostname: str = ""
    user: str = ""
    event_id: int | None = None
    process_id: int | None = None
    parent_process_id: int | None = None
    process_name: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    file_path: str = ""
    raw_reference: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.source_type = require_non_empty(self.source_type, "source_type")
        self.artifact_type = enum_from_value(
            ArtifactType,
            self.artifact_type,
            "artifact_type",
        )
        self.timestamp = parse_timestamp(self.timestamp)
        self.summary = require_non_empty(self.summary, "summary")
        self.record_id = require_non_empty(self.record_id, "record_id")
        for field_name in ("event_id", "process_id", "parent_process_id"):
            value = getattr(self, field_name)
            if value is not None:
                if isinstance(value, bool):
                    raise TypeError(f"{field_name} phải là số nguyên.")
                setattr(self, field_name, int(value))
        if self.file_path:
            self.file_path = portable_path(self.file_path, "file_path")
        if self.raw_reference:
            self.raw_reference = portable_path(
                self.raw_reference,
                "raw_reference",
            )
        self.attributes = dict(self.attributes)

    def dedup_key(self) -> str:
        data = self.to_dict()
        data.pop("record_id", None)
        canonical = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedRecord":
        return cls(
            case_id=data["case_id"],
            source_type=data["source_type"],
            artifact_type=data["artifact_type"],
            timestamp=data["timestamp"],
            summary=data["summary"],
            record_id=data.get("record_id") or new_id("REC"),
            hostname=data.get("hostname", ""),
            user=data.get("user", ""),
            event_id=data.get("event_id"),
            process_id=data.get("process_id"),
            parent_process_id=data.get("parent_process_id"),
            process_name=data.get("process_name", ""),
            source_ip=data.get("source_ip", ""),
            destination_ip=data.get("destination_ip", ""),
            file_path=data.get("file_path", ""),
            raw_reference=data.get("raw_reference", ""),
            attributes=dict(data.get("attributes", {})),
        )
