"""Normalize AmcacheParser rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from models.normalized_record import NormalizedRecord


class AmcacheParserParser(BaseParser):
    tool_id = "amcacheparser"
    artifact_type = ArtifactType.AMCACHE

    def parse_row(self, row: RowView, *, case_id: str, hostname: str, raw_reference: str) -> NormalizedRecord:
        name = row.text("Name", "FileName", "ProgramName")
        path = row.text("FullPath", "Path", "FilePath")
        return NormalizedRecord(
            case_id=case_id,
            source_type="amcacheparser_file",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(
                row,
                "FileKeyLastWriteTimestamp",
                "LastWriteTimestamp",
                "KeyLastWriteTimestamp",
            ),
            summary=f"Amcache entry: {name or path or 'unknown file'}",
            hostname=row.text("Computer", "Hostname", default=hostname),
            process_name=name,
            file_path=path,
            raw_reference=raw_reference,
            attributes=row.raw,
        )
