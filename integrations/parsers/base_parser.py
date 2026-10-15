"""Shared readers and field helpers for DFIR tool output parsers."""

from __future__ import annotations

import csv
import io
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from common.enums import ArtifactType
from common.exceptions import ToolIntegrationError
from common.time_utils import parse_timestamp
from models.normalized_record import NormalizedRecord

_FIELD_PATTERN = re.compile(r"[^a-z0-9]+")


class RowView:
    """Case-insensitive view that also ignores separators in column names."""

    def __init__(self, row: Mapping[str, Any]) -> None:
        self.raw = {str(key): value for key, value in row.items()}
        self._values = {_field_key(key): value for key, value in self.raw.items()}

    def get(self, *aliases: str, default: Any = "") -> Any:
        for alias in aliases:
            value = self._values.get(_field_key(alias))
            if value is not None and str(value).strip():
                return value
        return default

    def text(self, *aliases: str, default: str = "") -> str:
        value = self.get(*aliases, default=default)
        return str(value).strip() if value is not None else default

    def integer(self, *aliases: str) -> int | None:
        value = self.get(*aliases, default=None)
        if value is None or value == "":
            return None
        try:
            return int(str(value).strip(), 0)
        except ValueError as exc:
            raise ToolIntegrationError(
                f"Giá trị số nguyên không hợp lệ: {value}"
            ) from exc


class BaseParser(ABC):
    """Parse one supported output file into normalized project records."""

    tool_id: str
    artifact_type: ArtifactType

    def parse(
        self,
        path: str | Path,
        *,
        case_id: str,
        hostname: str = "",
        raw_reference: str | None = None,
    ) -> tuple[NormalizedRecord, ...]:
        candidate = Path(path).expanduser()
        if candidate.is_symlink():
            raise ToolIntegrationError(
                f"Output không được là symbolic link: {candidate}"
            )
        source = candidate.resolve()
        if not source.is_file():
            raise ToolIntegrationError(
                f"Không tìm thấy output hợp lệ để parse: {source}"
            )
        reference = raw_reference or source.as_posix()
        records: list[NormalizedRecord] = []
        for index, raw_row in enumerate(self._read_rows(source), start=1):
            if not isinstance(raw_row, Mapping):
                raise ToolIntegrationError(
                    f"{source.name}: record {index} phải là object."
                )
            row = RowView(raw_row)
            try:
                records.append(
                    self.parse_row(
                        row,
                        case_id=case_id,
                        hostname=hostname,
                        raw_reference=reference,
                    )
                )
            except ToolIntegrationError as exc:
                raise ToolIntegrationError(
                    f"{source.name}, record {index}: {exc}"
                ) from exc
            except (TypeError, ValueError, KeyError) as exc:
                raise ToolIntegrationError(
                    f"{source.name}, record {index} không hợp lệ: {exc}"
                ) from exc
        return tuple(records)

    @abstractmethod
    def parse_row(
        self,
        row: RowView,
        *,
        case_id: str,
        hostname: str,
        raw_reference: str,
    ) -> NormalizedRecord:
        """Convert one source row to the common schema."""

    def timestamp(self, row: RowView, *aliases: str):
        value = row.get(*aliases, default=None)
        if value is None:
            raise ToolIntegrationError(f"Thiếu timestamp ({', '.join(aliases)}).")
        try:
            return parse_timestamp(value)
        except (TypeError, ValueError) as exc:
            raise ToolIntegrationError(f"Timestamp không hợp lệ: {value}") from exc

    def summary(
        self,
        row: RowView,
        *aliases: str,
        fallback: str,
    ) -> str:
        return row.text(*aliases, default=fallback) or fallback

    def _read_rows(self, source: Path) -> Iterable[Mapping[str, Any]]:
        suffix = source.suffix.casefold()
        if suffix == ".csv":
            text = _read_text(source)
            return tuple(csv.DictReader(io.StringIO(text, newline="")))
        if suffix == ".json":
            try:
                payload = json.loads(_read_text(source))
            except json.JSONDecodeError as exc:
                raise ToolIntegrationError(f"JSON output không hợp lệ: {exc}") from exc
            if isinstance(payload, dict):
                for key in ("records", "items", "results"):
                    if isinstance(payload.get(key), list):
                        payload = payload[key]
                        break
                else:
                    payload = [payload]
            if not isinstance(payload, list):
                raise ToolIntegrationError(
                    "JSON output phải là object hoặc list object."
                )
            return tuple(payload)
        if suffix == ".jsonl":
            rows: list[Mapping[str, Any]] = []
            for line_number, line in enumerate(
                _read_text(source).splitlines(),
                start=1,
            ):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ToolIntegrationError(
                        f"JSONL không hợp lệ tại dòng {line_number}: {exc}"
                    ) from exc
                rows.append(value)
            return tuple(rows)
        raise ToolIntegrationError(
            f"Định dạng output chưa được hỗ trợ: {source.suffix}"
        )


def _field_key(value: str) -> str:
    return _FIELD_PATTERN.sub("", str(value).strip().casefold())


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ToolIntegrationError(f"Không thể giải mã output text: {path.name}")
