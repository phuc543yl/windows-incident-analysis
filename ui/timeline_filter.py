"""Filtering helpers for normalized timeline events shown by the Dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from common.time_utils import parse_timestamp


@dataclass(frozen=True, slots=True)
class TimelineFilter:
    """User-selected filters for the normalized incident timeline."""

    start: datetime | None = None
    end: datetime | None = None
    event_ids: frozenset[int] = frozenset()
    hostname: str = ""
    user: str = ""
    ip: str = ""

    @classmethod
    def from_text(
        cls,
        *,
        start: str = "",
        end: str = "",
        event_id: str = "",
        hostname: str = "",
        user: str = "",
        ip: str = "",
    ) -> "TimelineFilter":
        normalized_start = _optional_timestamp(start, "Thời gian từ")
        normalized_end = _optional_timestamp(end, "Thời gian đến")
        if (
            normalized_start is not None
            and normalized_end is not None
            and normalized_start > normalized_end
        ):
            raise ValueError(
                "Thời gian bắt đầu phải nhỏ hơn hoặc bằng thời gian kết thúc."
            )
        return cls(
            start=normalized_start,
            end=normalized_end,
            event_ids=_parse_event_ids(event_id),
            hostname=hostname.strip().casefold(),
            user=user.strip().casefold(),
            ip=ip.strip().casefold(),
        )

    def matches(self, event: dict[str, Any]) -> bool:
        """Return True when a timeline dictionary matches every active filter."""
        timestamp = parse_timestamp(event.get("timestamp"))
        if self.start is not None and timestamp < self.start:
            return False
        if self.end is not None and timestamp > self.end:
            return False

        details = event.get("details")
        details = details if isinstance(details, dict) else {}
        if self.event_ids:
            try:
                current_event_id = int(details.get("event_id"))
            except (TypeError, ValueError):
                return False
            if current_event_id not in self.event_ids:
                return False

        if self.hostname and self.hostname not in _text(event.get("hostname")):
            return False
        if self.user and self.user not in _text(event.get("user")):
            return False
        if self.ip:
            source_ip = _text(details.get("source_ip"))
            destination_ip = _text(details.get("destination_ip"))
            if self.ip not in source_ip and self.ip not in destination_ip:
                return False
        return True


def filter_timeline_events(
    events: Iterable[dict[str, Any]],
    criteria: TimelineFilter,
) -> tuple[dict[str, Any], ...]:
    """Filter timeline dictionaries without mutating the source collection."""
    return tuple(dict(event) for event in events if criteria.matches(event))


def _optional_timestamp(value: str, label: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    try:
        return parse_timestamp(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{label} không hợp lệ. Dùng ISO-8601, ví dụ 2026-07-30T14:00:00Z."
        ) from exc


def _parse_event_ids(value: str) -> frozenset[int]:
    text = value.strip()
    if not text:
        return frozenset()
    result: set[int] = set()
    for part in text.replace(";", ",").split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            event_id = int(candidate)
        except ValueError as exc:
            raise ValueError(
                "Event ID phải là số nguyên; có thể nhập nhiều ID cách nhau bằng dấu phẩy."
            ) from exc
        if event_id < 0:
            raise ValueError("Event ID không được là số âm.")
        result.add(event_id)
    return frozenset(result)


def _text(value: Any) -> str:
    return "" if value is None else str(value).casefold()
