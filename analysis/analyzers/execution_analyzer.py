"""Identify execution artifacts from commonly abused directories."""

from __future__ import annotations

from common.enums import ArtifactType, FindingSeverity
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer
from analysis.helpers import text_blob

_EXECUTION_ARTIFACTS = {
    ArtifactType.PREFETCH,
    ArtifactType.AMCACHE,
    ArtifactType.MFT,
}
_SUSPICIOUS_PATHS = (
    "/temp/",
    "/appdata/local/temp/",
    "/users/public/",
    "/recycle.bin/",
)


class ExecutionAnalyzer(BaseAnalyzer):
    analyzer_id = "execution_analyzer"

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if record.artifact_type not in _EXECUTION_ARTIFACTS:
            return None
        blob = text_blob(record)
        hits = tuple(value for value in _SUSPICIOUS_PATHS if value in blob)
        if not hits:
            return None
        return self.finding(
            record,
            title="Dấu vết thực thi từ thư mục đáng chú ý",
            description=record.summary,
            severity=FindingSeverity.MEDIUM,
            confidence_score=0.75,
            mitre_techniques=("T1204.002",),
            details={"path_hits": hits},
        )
