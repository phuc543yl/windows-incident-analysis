"""Normalize RECmd Registry rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from models.normalized_record import NormalizedRecord


class RECmdParser(BaseParser):
    tool_id = "recmd"
    artifact_type = ArtifactType.REGISTRY

    def parse_row(self, row: RowView, *, case_id: str, hostname: str, raw_reference: str) -> NormalizedRecord:
        key_path = row.text("KeyPath", "Path", "HivePath")
        value_name = row.text("ValueName", "Name")
        return NormalizedRecord(
            case_id=case_id,
            source_type="recmd_registry",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(
                row,
                "LastWriteTimestamp",
                "LastWriteTime",
                "Timestamp",
            ),
            summary=f"Registry entry: {key_path or value_name or 'unknown key'}",
            hostname=row.text("Computer", "Hostname", default=hostname),
            file_path=key_path,
            raw_reference=raw_reference,
            attributes=row.raw,
        )
