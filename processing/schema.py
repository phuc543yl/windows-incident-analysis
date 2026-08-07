"""Canonical envelopes and validation helpers for processed Case data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from common.exceptions import ProcessingError
from models.normalized_record import NormalizedRecord
from models.timeline_event import TimelineEvent

SCHEMA_VERSION = 1
RECORDS_FILENAME = "records.json"
PROCESSING_SUMMARY_FILENAME = "processing_summary.json"

REQUIRED_RECORD_FIELDS = frozenset(
    {
        "case_id",
        "source_type",
        "artifact_type",
        "timestamp",
        "summary",
    }
)

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "case_id": ("case_id", "caseid"),
    "source_type": ("source_type", "sourcetype", "source", "tool_id"),
    "artifact_type": (
        "artifact_type",
        "artifacttype",
        "artifact",
        "category",
    ),
    "timestamp": (
        "timestamp",
        "time",
        "datetime",
        "time_created",
        "timecreated",
    ),
    "summary": (
        "summary",
        "title",
        "message",
        "description",
        "details",
    ),
    "record_id": ("record_id", "recordid"),
    "hostname": ("hostname", "computer", "computer_name"),
    "user": ("user", "username", "user_name"),
    "event_id": ("event_id", "eventid"),
    "process_id": ("process_id", "processid", "pid"),
    "parent_process_id": (
        "parent_process_id",
        "parentprocessid",
        "parent_pid",
        "ppid",
    ),
    "process_name": ("process_name", "processname", "image"),
    "source_ip": ("source_ip", "sourceip", "src_ip", "srcip"),
    "destination_ip": (
        "destination_ip",
        "destinationip",
        "dst_ip",
        "dstip",
    ),
    "file_path": ("file_path", "filepath", "path"),
    "raw_reference": ("raw_reference", "rawreference"),
    "attributes": ("attributes",),
}


@dataclass(frozen=True, slots=True)
class ProcessingResult:
    case_id: str
    input_count: int
    normalized_count: int
    duplicate_count: int
    timeline_count: int
    records: tuple[NormalizedRecord, ...]
    timeline: tuple[TimelineEvent, ...]
    records_path: Path | None = None
    timeline_path: Path | None = None
    summary_path: Path | None = None

    def __post_init__(self) -> None:
        if not self.case_id.strip():
            raise ValueError("case_id không được để trống.")
        for field_name in (
            "input_count",
            "normalized_count",
            "duplicate_count",
            "timeline_count",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} phải là số nguyên.")
            if value < 0:
                raise ValueError(f"{field_name} không được âm.")
        if self.normalized_count != len(self.records):
            raise ValueError("normalized_count không khớp records.")
        if self.timeline_count != len(self.timeline):
            raise ValueError("timeline_count không khớp timeline.")
        if self.input_count != self.normalized_count + self.duplicate_count:
            raise ValueError("Số lượng input/normalized/duplicate không khớp.")

    def summary_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": self.case_id,
            "input_count": self.input_count,
            "normalized_count": self.normalized_count,
            "duplicate_count": self.duplicate_count,
            "timeline_count": self.timeline_count,
            "records_path": (
                self.records_path.as_posix()
                if self.records_path is not None
                else None
            ),
            "timeline_path": (
                self.timeline_path.as_posix()
                if self.timeline_path is not None
                else None
            ),
        }


def records_envelope(
    case_id: str,
    records: Iterable[NormalizedRecord],
) -> dict[str, Any]:
    items = tuple(records)
    _require_same_case(case_id, (item.case_id for item in items))
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "record_count": len(items),
        "records": [item.to_dict() for item in items],
    }


def timeline_envelope(
    case_id: str,
    events: Iterable[TimelineEvent],
) -> dict[str, Any]:
    items = tuple(events)
    _require_same_case(case_id, (item.case_id for item in items))
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "event_count": len(items),
        "events": [item.to_dict() for item in items],
    }


def parse_records_envelope(
    data: Mapping[str, Any],
    *,
    expected_case_id: str | None = None,
) -> tuple[NormalizedRecord, ...]:
    _validate_envelope(data, "record_count", "records")
    case_id = _required_text(data.get("case_id"), "case_id")
    if expected_case_id is not None and case_id != expected_case_id:
        raise ProcessingError("Dữ liệu normalized không khớp Case.")
    try:
        records = tuple(
            NormalizedRecord.from_dict(item)
            for item in data["records"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessingError(
            f"Normalized record không hợp lệ: {exc}"
        ) from exc
    _require_same_case(case_id, (item.case_id for item in records))
    return records


def parse_timeline_envelope(
    data: Mapping[str, Any],
    *,
    expected_case_id: str | None = None,
) -> tuple[TimelineEvent, ...]:
    _validate_envelope(data, "event_count", "events")
    case_id = _required_text(data.get("case_id"), "case_id")
    if expected_case_id is not None and case_id != expected_case_id:
        raise ProcessingError("Timeline không khớp Case.")
    try:
        events = tuple(
            TimelineEvent.from_dict(item)
            for item in data["events"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessingError(f"Timeline event không hợp lệ: {exc}") from exc
    _require_same_case(case_id, (item.case_id for item in events))
    return events


def _validate_envelope(
    data: Mapping[str, Any],
    count_field: str,
    items_field: str,
) -> None:
    if not isinstance(data, Mapping):
        raise ProcessingError("Processed JSON phải là object.")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ProcessingError("schema_version không được hỗ trợ.")
    items = data.get(items_field)
    if not isinstance(items, list):
        raise ProcessingError(f"{items_field} phải là list.")
    count = data.get(count_field)
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count != len(items)
    ):
        raise ProcessingError(f"{count_field} không chính xác.")
    if any(not isinstance(item, dict) for item in items):
        raise ProcessingError(f"{items_field} chỉ được chứa object.")


def _require_same_case(
    case_id: str,
    values: Iterable[str],
) -> None:
    if any(value != case_id for value in values):
        raise ProcessingError("Processed data chứa record khác Case.")


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProcessingError(f"{field_name} không được để trống.")
    return value.strip()
