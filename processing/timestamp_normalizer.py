"""Normalize forensic timestamps to timezone-aware UTC datetimes."""

from __future__ import annotations

from datetime import datetime, tzinfo
from typing import Any

from dateutil.tz import gettz

from common.exceptions import ProcessingError
from common.time_utils import (
    UTC,
    parse_timestamp,
    to_iso8601,
    windows_filetime_to_datetime,
)


class TimestampNormalizer:
    def __init__(self, default_timezone: str = "UTC") -> None:
        self.default_timezone = _timezone(
            default_timezone,
            "Timezone",
        )
        self.default_timezone_name = default_timezone

    def normalize(
        self,
        value: Any,
        *,
        format_hint: str | None = None,
        source_timezone: str | None = None,
    ) -> datetime:
        hint = (format_hint or "").strip().casefold()
        if hint not in {"", "iso8601", "unix", "filetime"}:
            raise ProcessingError(
                f"format_hint không được hỗ trợ: {format_hint}"
            )
        try:
            if hint == "filetime":
                return windows_filetime_to_datetime(_integer(value))
            if hint == "unix":
                return parse_timestamp(_number(value))
            if isinstance(value, datetime):
                return self._normalize_datetime(value, source_timezone)
            if isinstance(value, str) and hint in {"", "iso8601"}:
                return self._normalize_text(value, source_timezone)
            return parse_timestamp(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ProcessingError(
                f"Timestamp không hợp lệ: {value}"
            ) from exc

    def to_text(self, value: Any, **kwargs: Any) -> str:
        return to_iso8601(self.normalize(value, **kwargs))

    def _normalize_text(
        self,
        value: str,
        source_timezone: str | None,
    ) -> datetime:
        text = value.strip()
        if not text:
            raise ValueError("Timestamp không được để trống.")
        iso_text = (
            f"{text[:-1]}+00:00"
            if text.endswith(("Z", "z"))
            else text
        )
        parsed = datetime.fromisoformat(iso_text)
        return self._normalize_datetime(parsed, source_timezone)

    def _normalize_datetime(
        self,
        value: datetime,
        source_timezone: str | None,
    ) -> datetime:
        if value.tzinfo is not None:
            return value.astimezone(UTC)
        timezone_value = self.default_timezone
        if source_timezone is not None:
            timezone_value = _timezone(
                source_timezone,
                "Timezone nguồn",
            )
        return value.replace(tzinfo=timezone_value).astimezone(UTC)


def _integer(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("Boolean không phải số nguyên.")
    return int(str(value).strip())


def _number(value: Any) -> float:
    if isinstance(value, bool):
        raise TypeError("Boolean không phải số.")
    return float(str(value).strip())


def _timezone(value: str, field_name: str) -> tzinfo:
    if not isinstance(value, str) or not value.strip():
        raise ProcessingError(f"{field_name} không hợp lệ: {value}")
    timezone_value = gettz(value.strip())
    if timezone_value is None:
        raise ProcessingError(f"{field_name} không hợp lệ: {value}")
    return timezone_value
