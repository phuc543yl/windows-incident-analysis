"""UTF-8 JSON helpers with deterministic and atomic writes."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePath
from typing import Any

from common.constants import DEFAULT_ENCODING
from common.exceptions import JsonFileError
from common.time_utils import to_iso8601

_MISSING = object()


def json_default(value: Any) -> Any:
    """Serialize common project types without silently stringifying objects."""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return to_iso8601(value)
    if isinstance(value, PurePath):
        # Persist one portable representation instead of OS-specific separators.
        return value.as_posix()
    if isinstance(value, set):
        return sorted(value, key=str)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    raise TypeError(
        f"Đối tượng kiểu {type(value).__name__} không thể chuyển thành JSON."
    )


def read_json(path: str | Path, *, default: Any = _MISSING) -> Any:
    """Read a JSON file.

    A deep copy of ``default`` is returned when the file does not exist. Without
    a default, a missing or malformed file raises ``JsonFileError``.
    """
    json_path = Path(path)
    if not json_path.exists():
        if default is not _MISSING:
            return copy.deepcopy(default)
        raise JsonFileError(f"Không tìm thấy file JSON: {json_path}")
    if not json_path.is_file():
        raise JsonFileError(f"Đường dẫn JSON không phải file: {json_path}")

    try:
        with json_path.open("r", encoding=f"{DEFAULT_ENCODING}-sig") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise JsonFileError(
            f"JSON không hợp lệ trong {json_path} "
            f"(dòng {exc.lineno}, cột {exc.colno}): {exc.msg}"
        ) from exc
    except OSError as exc:
        raise JsonFileError(f"Không thể đọc file JSON {json_path}: {exc}") from exc


def read_json_object(path: str | Path, *, default: Any = _MISSING) -> dict[str, Any]:
    """Read JSON and require the top-level value to be an object."""
    data = read_json(path, default=default)
    if not isinstance(data, dict):
        raise JsonFileError(f"JSON trong {path} phải có object ở cấp cao nhất.")
    return data


def write_json(
    path: str | Path,
    data: Any,
    *,
    indent: int = 2,
    atomic: bool = True,
) -> Path:
    """Write JSON in UTF-8, replacing the destination atomically by default."""
    json_path = Path(path)
    try:
        payload = json.dumps(
            data,
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
            allow_nan=False,
            default=json_default,
        )
    except (TypeError, ValueError) as exc:
        raise JsonFileError(f"Không thể tuần tự hóa dữ liệu JSON: {exc}") from exc

    try:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        if atomic:
            _atomic_write_text(json_path, f"{payload}\n")
        else:
            json_path.write_text(
                f"{payload}\n",
                encoding=DEFAULT_ENCODING,
            )
    except OSError as exc:
        raise JsonFileError(f"Không thể ghi file JSON {json_path}: {exc}") from exc
    return json_path


def append_jsonl(path: str | Path, record: Any) -> Path:
    """Append one compact JSON record to a JSON Lines file."""
    jsonl_path = Path(path)
    try:
        payload = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
            default=json_default,
        )
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with jsonl_path.open("a", encoding=DEFAULT_ENCODING, newline="\n") as handle:
            handle.write(f"{payload}\n")
            handle.flush()
    except (OSError, TypeError, ValueError) as exc:
        raise JsonFileError(f"Không thể ghi JSON Lines {jsonl_path}: {exc}") from exc
    return jsonl_path


def _atomic_write_text(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding=DEFAULT_ENCODING, newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
