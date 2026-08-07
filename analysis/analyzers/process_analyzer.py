"""Identify process records that need analyst review."""

from __future__ import annotations

from common.enums import ArtifactType, FindingSeverity
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer
from analysis.helpers import text_blob

_PROCESS_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}
_INDICATORS = (
    "-enc",
    "-encodedcommand",
    "-executionpolicy bypass",
    "downloadstring",
    "invoke-expression",
    "invoke-webrequest",
)


class ProcessAnalyzer(BaseAnalyzer):
    analyzer_id = "process_analyzer"

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if (
            record.artifact_type is not ArtifactType.PROCESSES
            and record.process_name.casefold() not in _PROCESS_NAMES
        ):
            return None
        blob = text_blob(record)
        hits = tuple(value for value in _INDICATORS if value in blob)
        if not hits:
            return None
        return self.finding(
            record,
            title="Tiến trình sử dụng command đáng chú ý",
            description=record.summary,
            severity=FindingSeverity.MEDIUM,
            confidence_score=min(0.95, 0.65 + 0.1 * len(hits)),
            mitre_techniques=("T1059.001",),
            details={"indicator_hits": hits},
        )
