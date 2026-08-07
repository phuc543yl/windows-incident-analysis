"""Convert parser output and generic mappings to NormalizedRecord."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from common.enums import ArtifactType
from common.exceptions import ProcessingError
from models import new_id
from models.normalized_record import NormalizedRecord
from processing.schema import FIELD_ALIASES
from processing.timestamp_normalizer import TimestampNormalizer

_KEY_PATTERN = re.compile(r"[^a-z0-9]+")


class RecordNormalizer:
    def __init__(
        self,
        *,
        timestamp_normalizer: TimestampNormalizer | None = None,
        preserve_raw_values: bool = True,
    ) -> None:
        self.timestamp_normalizer = (
            timestamp_normalizer or TimestampNormalizer()
        )
        self.preserve_raw_values = bool(preserve_raw_values)

    def normalize(
        self,
        value: NormalizedRecord | Mapping[str, Any],
        *,
        case_id: str | None = None,
        source_type: str | None = None,
        artifact_type: ArtifactType | str | None = None,
        raw_reference: str | None = None,
        source_timezone: str | None = None,
    ) -> NormalizedRecord:
        raw = (
            value.to_dict()
            if isinstance(value, NormalizedRecord)
            else dict(value)
        )
        view = _MappingView(raw)
        resolved_case_id = _choose(
            case_id,
            view.get("case_id"),
            field_name="case_id",
        )
        if case_id is not None:
            existing_case_id = view.get("case_id")
            if existing_case_id and str(existing_case_id) != case_id:
                raise ProcessingError("Record không khớp Case.")
        resolved_source = _choose(
            source_type,
            view.get("source_type"),
            field_name="source_type",
        )
        resolved_artifact = _choose(
            artifact_type,
            view.get("artifact_type"),
            field_name="artifact_type",
        )
        timestamp = view.get("timestamp")
        if timestamp in (None, ""):
            raise ProcessingError("Record thiếu timestamp.")
        summary = _required_text(view.get("summary"), "summary")

        attributes = view.get("attributes", default={})
        if attributes in (None, ""):
            attributes = {}
        if not isinstance(attributes, Mapping):
            raise ProcessingError("attributes phải là object.")
        merged_attributes = dict(attributes)
        if self.preserve_raw_values:
            recognized = view.recognized_source_keys()
            for key, item in raw.items():
                if key not in recognized and key != "attributes":
                    merged_attributes.setdefault(str(key), item)

        normalized_timestamp = self.timestamp_normalizer.normalize(
            timestamp,
            source_timezone=source_timezone,
        )
        try:
            return NormalizedRecord(
                case_id=str(resolved_case_id),
                source_type=str(resolved_source),
                artifact_type=resolved_artifact,
                timestamp=normalized_timestamp,
                summary=summary,
                record_id=(
                    str(view.get("record_id"))
                    if view.get("record_id")
                    else new_id("REC")
                ),
                hostname=_text(view.get("hostname")),
                user=_text(view.get("user")),
                event_id=_optional_integer(view.get("event_id")),
                process_id=_optional_integer(view.get("process_id")),
                parent_process_id=_optional_integer(
                    view.get("parent_process_id")
                ),
                process_name=_text(view.get("process_name")),
                source_ip=_text(view.get("source_ip")),
                destination_ip=_text(view.get("destination_ip")),
                file_path=_text(view.get("file_path")),
                raw_reference=_text(
                    raw_reference
                    if raw_reference is not None
                    else view.get("raw_reference")
                ),
                attributes=merged_attributes,
            )
        except ProcessingError:
            raise
        except (TypeError, ValueError) as exc:
            raise ProcessingError(f"Record không hợp lệ: {exc}") from exc

    def normalize_many(
        self,
        values: Iterable[NormalizedRecord | Mapping[str, Any]],
        **kwargs: Any,
    ) -> tuple[NormalizedRecord, ...]:
        records: list[NormalizedRecord] = []
        for index, value in enumerate(values, start=1):
            try:
                records.append(self.normalize(value, **kwargs))
            except ProcessingError as exc:
                raise ProcessingError(
                    f"Record {index}: {exc}"
                ) from exc
        return tuple(records)


class _MappingView:
    def __init__(self, data: Mapping[str, Any]) -> None:
        self.data = data
        self.normalized = {
            _key(key): (str(key), value)
            for key, value in data.items()
        }

    def get(self, field_name: str, default: Any = None) -> Any:
        for alias in FIELD_ALIASES[field_name]:
            pair = self.normalized.get(_key(alias))
            if pair is not None and pair[1] not in (None, ""):
                return pair[1]
        return default

    def recognized_source_keys(self) -> set[str]:
        aliases = {
            _key(alias)
            for values in FIELD_ALIASES.values()
            for alias in values
        }
        return {
            original
            for normalized, (original, _) in self.normalized.items()
            if normalized in aliases
        }


def _key(value: Any) -> str:
    return _KEY_PATTERN.sub("", str(value).strip().casefold())


def _choose(
    preferred: Any,
    fallback: Any,
    *,
    field_name: str,
) -> Any:
    value = preferred if preferred not in (None, "") else fallback
    if value in (None, ""):
        raise ProcessingError(f"Record thiếu {field_name}.")
    return value


def _required_text(value: Any, field_name: str) -> str:
    text = _text(value)
    if not text:
        raise ProcessingError(f"Record thiếu {field_name}.")
    return text


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _optional_integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ProcessingError("Boolean không phải số nguyên.")
    try:
        return int(str(value).strip(), 0)
    except ValueError as exc:
        raise ProcessingError(
            f"Giá trị số nguyên không hợp lệ: {value}"
        ) from exc
