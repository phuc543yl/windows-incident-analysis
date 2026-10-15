"""Build a deterministic chronological view from normalized records."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime

from common.enums import ArtifactType
from common.exceptions import ProcessingError
from common.time_utils import parse_timestamp
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from models.timeline_event import TimelineEvent

_SORT_PRIORITY = {
    ArtifactType.EVENT_LOGS: 10,
    ArtifactType.PROCESSES: 20,
    ArtifactType.NETWORK: 30,
    ArtifactType.SERVICES: 40,
    ArtifactType.STARTUP: 50,
    ArtifactType.SCHEDULED_TASKS: 55,
    ArtifactType.PREFETCH: 60,
    ArtifactType.AMCACHE: 65,
    ArtifactType.REGISTRY: 70,
    ArtifactType.MFT: 80,
}


class TimelineBuilder:
    def link_analysis(
        self,
        timeline: Iterable[TimelineEvent],
        *,
        findings: Iterable[Finding],
        alerts: Iterable[Alert],
    ) -> tuple[TimelineEvent, ...]:
        """Replace old result links using the current source-record IDs."""
        findings_by_record: dict[str, set[str]] = defaultdict(set)
        alerts_by_record: dict[str, set[str]] = defaultdict(set)
        for finding in findings:
            for record_id in finding.source_record_ids:
                findings_by_record[record_id].add(finding.finding_id)
        for alert in alerts:
            for record_id in alert.source_record_ids:
                alerts_by_record[record_id].add(alert.alert_id)
        return tuple(
            replace(
                event,
                finding_ids=tuple(
                    sorted(
                        {
                            finding_id
                            for record_id in event.source_record_ids
                            for finding_id in findings_by_record[record_id]
                        }
                    )
                ),
                alert_ids=tuple(
                    sorted(
                        {
                            alert_id
                            for record_id in event.source_record_ids
                            for alert_id in alerts_by_record[record_id]
                        }
                    )
                ),
            )
            for event in timeline
        )

    def build(
        self,
        records: Iterable[NormalizedRecord],
        *,
        start: datetime | str | None = None,
        end: datetime | str | None = None,
    ) -> tuple[TimelineEvent, ...]:
        normalized_start = parse_timestamp(start) if start is not None else None
        normalized_end = parse_timestamp(end) if end is not None else None
        if (
            normalized_start is not None
            and normalized_end is not None
            and normalized_start > normalized_end
        ):
            raise ProcessingError("Khoảng thời gian timeline không hợp lệ.")

        events: list[TimelineEvent] = []
        id_occurrences: dict[str, int] = {}
        case_id: str | None = None
        for record in records:
            if not isinstance(record, NormalizedRecord):
                raise TypeError("TimelineBuilder chỉ nhận NormalizedRecord.")
            if case_id is None:
                case_id = record.case_id
            elif record.case_id != case_id:
                raise ProcessingError("Không thể tạo timeline từ nhiều Case.")
            if normalized_start is not None and record.timestamp < normalized_start:
                continue
            if normalized_end is not None and record.timestamp > normalized_end:
                continue
            occurrence = id_occurrences.get(record.record_id, 0)
            id_occurrences[record.record_id] = occurrence + 1
            events.append(self._from_record(record, occurrence))
        return tuple(sorted(events, key=lambda item: item.sort_key()))

    def _from_record(
        self,
        record: NormalizedRecord,
        occurrence: int,
    ) -> TimelineEvent:
        details = {
            "artifact_type": record.artifact_type.value,
            "source_type": record.source_type,
            "event_id": record.event_id,
            "process_id": record.process_id,
            "parent_process_id": record.parent_process_id,
            "process_name": record.process_name,
            "source_ip": record.source_ip,
            "destination_ip": record.destination_ip,
            "file_path": record.file_path,
            "raw_reference": record.raw_reference,
            "attributes": dict(record.attributes),
        }
        return TimelineEvent(
            case_id=record.case_id,
            timestamp=record.timestamp,
            event_type=record.artifact_type.value,
            summary=record.summary,
            timeline_event_id=_timeline_id(record, occurrence),
            hostname=record.hostname,
            user=record.user,
            source_record_ids=(record.record_id,),
            sort_priority=_SORT_PRIORITY.get(record.artifact_type, 100),
            details=details,
        )


def _timeline_id(record: NormalizedRecord, occurrence: int) -> str:
    digest = hashlib.sha256(
        (f"{record.case_id}\0{record.record_id}\0{occurrence}").encode("utf-8")
    ).hexdigest()
    return f"TL-{digest[:32]}"
