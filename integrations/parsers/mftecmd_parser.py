"""Normalize MFTECmd file-system rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from models.normalized_record import NormalizedRecord


class MFTECmdParser(BaseParser):
    tool_id = "mftecmd"
    artifact_type = ArtifactType.MFT

    def parse_row(self, row: RowView, *, case_id: str, hostname: str, raw_reference: str) -> NormalizedRecord:
        name = row.text("FileName", "Name")
        path = row.text("FullPath", "FilePath", "ParentPath")
        return NormalizedRecord(
            case_id=case_id,
            source_type="mftecmd_file",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(
                row,
                "Modified0x10",
                "Created0x10",
                "Created0x30",
            ),
            summary=f"MFT entry: {path or name or 'unknown file'}",
            hostname=row.text("Computer", "Hostname", default=hostname),
            file_path=path or name,
            raw_reference=raw_reference,
            attributes=row.raw,
        )
