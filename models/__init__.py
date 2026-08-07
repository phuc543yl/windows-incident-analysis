"""Shared model helpers.

The package keeps models independent of storage and service layers. Every model
can therefore be serialized to JSON-safe dictionaries without importing a
repository, database, or UI component.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import PurePath
from typing import Any, TypeVar
from uuid import uuid4

from common.time_utils import parse_timestamp, to_iso8601

EnumType = TypeVar("EnumType", bound=Enum)


def new_id(prefix: str) -> str:
    normalized = require_non_empty(prefix, "prefix").upper()
    return f"{normalized}-{uuid4().hex}"


def require_non_empty(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} không được để trống.")
    return value.strip()


def enum_from_value(
    enum_type: type[EnumType],
    value: EnumType | str,
    field_name: str,
) -> EnumType:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise ValueError(
            f"{field_name} không hợp lệ: {value}. Giá trị cho phép: {allowed}."
        ) from exc


def optional_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    return parse_timestamp(value)


def string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    items = (value,) if isinstance(value, str) else value
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = require_non_empty(str(item), "list item")
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return tuple(result)


def portable_path(value: Any, field_name: str) -> str:
    text = require_non_empty(str(value), field_name)
    return text.replace("\\", "/")


def validate_score(value: int | float, field_name: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} phải là số.")
    score = float(value)
    if not 0 <= score <= maximum:
        raise ValueError(f"{field_name} phải nằm trong khoảng 0-{maximum}.")
    return score


def to_json_value(value: Any) -> Any:
    """Recursively convert model values into JSON-compatible primitives."""
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: to_json_value(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return to_iso8601(value)
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, dict):
        return {
            str(key): to_json_value(nested)
            for key, nested in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [to_json_value(item) for item in value]
    return value


__all__ = [
    "enum_from_value",
    "new_id",
    "optional_timestamp",
    "portable_path",
    "require_non_empty",
    "string_tuple",
    "to_json_value",
    "validate_score",
]
