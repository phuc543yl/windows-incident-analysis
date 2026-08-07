"""Identify Registry autorun persistence context."""

from __future__ import annotations

from common.enums import ArtifactType, FindingSeverity
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer
from analysis.helpers import text_blob

_AUTORUN_PATHS = (
    "/software/microsoft/windows/currentversion/run",
    "/software/microsoft/windows/currentversion/runonce",
)


class RegistryAnalyzer(BaseAnalyzer):
    analyzer_id = "registry_analyzer"

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if record.artifact_type is not ArtifactType.REGISTRY:
            return None
        blob = text_blob(record)
        if not any(value in blob for value in _AUTORUN_PATHS):
            return None
        return self.finding(
            record,
            title="Registry autorun cần kiểm tra",
            description=record.summary,
            severity=FindingSeverity.MEDIUM,
            confidence_score=0.8,
            mitre_techniques=("T1547.001",),
            details={"registry_path": record.file_path},
        )
