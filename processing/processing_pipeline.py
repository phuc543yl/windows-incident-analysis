"""Orchestrate normalization, deduplication, timeline creation, and storage."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.exceptions import JsonFileError, ProcessingError
from common.json_utils import read_json_object, write_json
from models.normalized_record import NormalizedRecord
from models.timeline_event import TimelineEvent
from processing.deduplicator import (
    DeduplicationResult,
    RecordDeduplicator,
)
from processing.normalizer import RecordNormalizer
from processing.schema import (
    PROCESSING_SUMMARY_FILENAME,
    RECORDS_FILENAME,
    ProcessingResult,
    parse_records_envelope,
    parse_timeline_envelope,
    records_envelope,
    timeline_envelope,
)
from processing.timeline_builder import TimelineBuilder
from processing.timestamp_normalizer import TimestampNormalizer


class ProcessingPipeline:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        normalizer: RecordNormalizer | None = None,
        deduplicator: RecordDeduplicator | None = None,
        timeline_builder: TimelineBuilder | None = None,
        actor: str = "system",
    ) -> None:
        self.repository = CaseRepository(root)
        settings = _processing_settings(self.repository.project)
        self.deduplicate_records = bool(
            settings.get("deduplicate_records", True)
        )
        self.normalizer = normalizer or RecordNormalizer(
            timestamp_normalizer=TimestampNormalizer(
                str(settings.get("normalize_timezone", "UTC"))
            ),
            preserve_raw_values=bool(
                settings.get("preserve_raw_values", True)
            ),
        )
        self.deduplicator = deduplicator or RecordDeduplicator()
        self.timeline_builder = timeline_builder or TimelineBuilder()
        self.actor = actor.strip() or "system"

    def process(
        self,
        *,
        case_id: str,
        records: Iterable[NormalizedRecord | Mapping[str, Any]],
        persist: bool = True,
        deduplicate: bool | None = None,
    ) -> ProcessingResult:
        case = self.repository.require_open(case_id)
        input_records = tuple(records)
        normalized = self.normalizer.normalize_many(
            input_records,
            case_id=case.case_id,
        )
        should_deduplicate = (
            self.deduplicate_records
            if deduplicate is None
            else bool(deduplicate)
        )
        if should_deduplicate:
            deduplication = self.deduplicator.deduplicate(normalized)
        else:
            deduplication = DeduplicationResult(records=normalized)
        timeline = self.timeline_builder.build(deduplication.records)

        records_path: Path | None = None
        timeline_path: Path | None = None
        summary_path: Path | None = None
        if persist:
            paths = self.repository.paths(case.case_id)
            records_path = paths.normalized / RECORDS_FILENAME
            timeline_path = paths.timeline_json
            summary_path = (
                paths.normalized / PROCESSING_SUMMARY_FILENAME
            )
            write_json(
                records_path,
                records_envelope(case.case_id, deduplication.records),
            )
            write_json(
                timeline_path,
                timeline_envelope(case.case_id, timeline),
            )

        result = ProcessingResult(
            case_id=case.case_id,
            input_count=len(input_records),
            normalized_count=len(deduplication.records),
            duplicate_count=deduplication.duplicate_count,
            timeline_count=len(timeline),
            records=deduplication.records,
            timeline=timeline,
            records_path=records_path,
            timeline_path=timeline_path,
            summary_path=summary_path,
        )
        if persist:
            write_json(summary_path, result.summary_dict())
            AuditLogger(case.case_id, self.repository.project).log(
                "processing_completed",
                actor=self.actor,
                details={
                    "input_count": result.input_count,
                    "normalized_count": result.normalized_count,
                    "duplicate_count": result.duplicate_count,
                    "timeline_count": result.timeline_count,
                },
            )
        return result

    def load_records(
        self,
        case_id: str,
    ) -> tuple[NormalizedRecord, ...]:
        paths = self.repository.paths(case_id)
        self.repository.load_case(case_id)
        try:
            data = read_json_object(paths.normalized / RECORDS_FILENAME)
            return parse_records_envelope(
                data,
                expected_case_id=paths.case_id,
            )
        except JsonFileError as exc:
            raise ProcessingError(str(exc)) from exc

    def load_timeline(
        self,
        case_id: str,
    ) -> tuple[TimelineEvent, ...]:
        paths = self.repository.paths(case_id)
        self.repository.load_case(case_id)
        try:
            data = read_json_object(paths.timeline_json)
            return parse_timeline_envelope(
                data,
                expected_case_id=paths.case_id,
            )
        except JsonFileError as exc:
            raise ProcessingError(str(exc)) from exc


def _processing_settings(root: Path) -> dict[str, Any]:
    try:
        settings = read_json_object(root / "config" / "settings.json")
    except JsonFileError as exc:
        raise ProcessingError(str(exc)) from exc
    processing = settings.get("processing", {})
    if not isinstance(processing, dict):
        raise ProcessingError(
            "settings.json phải có processing là object."
        )
    return dict(processing)
