from __future__ import annotations

from common.enums import ArtifactType, FindingSeverity
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer
from analysis.helpers import service_name, text_blob


class ServiceAnalyzer(BaseAnalyzer):
    analyzer_id = "service_analyzer"

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if (
            record.artifact_type is not ArtifactType.SERVICES
            and record.event_id not in {7036, 7040, 7045}
        ):
            return None
        blob = text_blob(record)
        if record.event_id == 7036 and "stopped" in blob:
            title = "Dịch vụ Windows chuyển sang trạng thái dừng"
            severity = FindingSeverity.HIGH
            technique = ("T1489",)
        elif record.event_id in {7040, 7045}:
            title = "Cấu hình dịch vụ Windows thay đổi"
            severity = FindingSeverity.HIGH
            technique = ("T1543.003",)
        else:
            return None
        return self.finding(
            record,
            title=title,
            description=record.summary,
            severity=severity,
            confidence_score=0.8,
            mitre_techniques=technique,
            details={"service_name": service_name(record)},
        )