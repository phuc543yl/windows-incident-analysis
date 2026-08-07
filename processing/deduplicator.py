"""Stable duplicate removal for normalized forensic records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from common.exceptions import ProcessingError
from models.normalized_record import NormalizedRecord


@dataclass(frozen=True, slots=True)
class DeduplicationResult:
    records: tuple[NormalizedRecord, ...]
    duplicate_record_ids: tuple[str, ...] = ()

    @property
    def input_count(self) -> int:
        return len(self.records) + len(self.duplicate_record_ids)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicate_record_ids)


class RecordDeduplicator:
    def deduplicate(
        self,
        records: Iterable[NormalizedRecord],
    ) -> DeduplicationResult:
        unique: list[NormalizedRecord] = []
        duplicate_ids: list[str] = []
        seen: dict[str, str] = {}
        case_id: str | None = None

        for record in records:
            if not isinstance(record, NormalizedRecord):
                raise TypeError("deduplicate chỉ nhận NormalizedRecord.")
            if case_id is None:
                case_id = record.case_id
            elif record.case_id != case_id:
                raise ProcessingError(
                    "Không thể loại trùng record từ nhiều Case."
                )
            fingerprint = record.dedup_key()
            if fingerprint in seen:
                duplicate_ids.append(record.record_id)
                continue
            seen[fingerprint] = record.record_id
            unique.append(record)

        return DeduplicationResult(
            records=tuple(unique),
            duplicate_record_ids=tuple(duplicate_ids),
        )
