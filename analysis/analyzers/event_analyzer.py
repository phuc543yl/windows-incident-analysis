from __future__ import annotations

from common.enums import ArtifactType, FindingSeverity
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer

_EVENTS = {
    4698: ("Scheduled Task được tạo", FindingSeverity.MEDIUM),
    4657: ("Registry value bị thay đổi", FindingSeverity.MEDIUM),
    1100: ("Dịch vụ Event Log bị tắt", FindingSeverity.HIGH),
    1102: ("Security log bị xóa", FindingSeverity.CRITICAL),
    104: ("Event log bị xóa", FindingSeverity.HIGH),
    7040: ("Startup type dịch vụ thay đổi", FindingSeverity.MEDIUM),
    7045: ("Dịch vụ mới được cài đặt", FindingSeverity.HIGH),
}


class EventAnalyzer(BaseAnalyzer):
    analyzer_id = "event_analyzer"

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if (
            record.artifact_type is not ArtifactType.EVENT_LOGS
            or record.event_id not in _EVENTS
        ):
            return None
        title, severity = _EVENTS[record.event_id]
        return self.finding(
            record,
            title=title,
            description=record.summary,
            severity=severity,
            confidence_score=0.9,
            details={"event_id": record.event_id},
        )