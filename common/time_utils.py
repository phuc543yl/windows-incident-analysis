"""Timezone-safe helpers for forensic timestamps."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TypeAlias

TimestampInput: TypeAlias = datetime | str | int | float
UTC = timezone.utc
WINDOWS_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def utc_now() -> datetime:
    """Return an aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Convert a datetime to UTC; treat a naive value as already UTC."""
    if not isinstance(value, datetime):
        raise TypeError("value phải là datetime.")
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_timestamp(value: TimestampInput) -> datetime:
    """Parse a supported timestamp and return an aware UTC datetime.

    Supported inputs:
    - aware or naive ``datetime`` (naive values are interpreted as UTC);
    - Unix seconds as ``int`` or ``float``;
    - ISO-8601 text, including a trailing ``Z``.
    """
    if isinstance(value, bool):
        raise TypeError("Boolean không phải timestamp hợp lệ.")
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"Unix timestamp không hợp lệ: {value}") from exc
    if not isinstance(value, str):
        raise TypeError(f"Không hỗ trợ kiểu timestamp: {type(value).__name__}")

    text = value.strip()
    if not text:
        raise ValueError("Timestamp không được để trống.")
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"Timestamp ISO-8601 không hợp lệ: {value}") from exc
    return ensure_utc(parsed)


def to_iso8601(
    value: TimestampInput,
    *,
    timespec: str = "milliseconds",
) -> str:
    """Serialize a timestamp as an ISO-8601 UTC string ending in ``Z``."""
    normalized = parse_timestamp(value)
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def utc_now_iso(*, timespec: str = "milliseconds") -> str:
    return to_iso8601(utc_now(), timespec=timespec)


def filename_timestamp(value: TimestampInput | None = None) -> str:
    """Return a compact UTC timestamp safe for Windows filenames."""
    normalized = utc_now() if value is None else parse_timestamp(value)
    return normalized.strftime("%Y%m%dT%H%M%SZ")


def windows_filetime_to_datetime(value: int) -> datetime:
    """Convert Windows FILETIME (100-ns ticks since 1601) to UTC."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("Windows FILETIME phải là số nguyên.")
    if value < 0:
        raise ValueError("Windows FILETIME không được âm.")

    seconds, remainder = divmod(value, 10_000_000)
    microseconds = remainder // 10
    try:
        return WINDOWS_FILETIME_EPOCH + timedelta(
            seconds=seconds,
            microseconds=microseconds,
        )
    except OverflowError as exc:
        raise ValueError("Windows FILETIME nằm ngoài phạm vi hỗ trợ.") from exc
def validate_time_range(
    start: TimestampInput,
    end: TimestampInput,
) -> tuple[datetime, datetime]:
    """Normalize a time range and ensure start is not after end."""
    normalized_start = parse_timestamp(start)
    normalized_end = parse_timestamp(end)
    if normalized_start > normalized_end:
        raise ValueError("Thời gian bắt đầu phải nhỏ hơn hoặc bằng kết thúc.")
    return normalized_start, normalized_end
