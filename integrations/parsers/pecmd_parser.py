"""Normalize PECmd Prefetch rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from models.normalized_record import NormalizedRecord


class PECmdParser(BaseParser):
    tool_id = "pecmd"
    artifact_type = ArtifactType.PREFETCH

    def parse_row(self, row: RowView, *, case_id: str, hostname: str, raw_reference: str) -> NormalizedRecord:
        executable = row.text("ExecutableName", "Executable", "SourceFilename", "FileName")
        return NormalizedRecord(
            case_id=case_id,
            source_type="pecmd_prefetch",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(row, "LastRun", "LastRun0", "SourceCreated"),
            summary=f"Prefetch execution: {executable or 'unknown executable'}",
            hostname=row.text("Computer", "Hostname", default=hostname),
            process_name=executable,
            file_path=row.text("SourceFilename", "FullPath", "FilePath"),
            raw_reference=raw_reference,
            attributes=row.raw,
        )
