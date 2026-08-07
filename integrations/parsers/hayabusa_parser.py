"""Normalize Hayabusa timeline rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from models.normalized_record import NormalizedRecord


class HayabusaParser(BaseParser):
    tool_id = "hayabusa"
    artifact_type = ArtifactType.EVENT_LOGS

    def parse_row(self, row: RowView, *, case_id: str, hostname: str, raw_reference: str) -> NormalizedRecord:
        rule = self.summary(row, "RuleTitle", "Title", "Details", fallback="Windows event")
        return NormalizedRecord(
            case_id=case_id,
            source_type="hayabusa_event",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(row, "Timestamp", "Datetime", "TimeCreated"),
            summary=rule,
            hostname=row.text("Computer", "Hostname", default=hostname),
            user=row.text("User", "UserName", "TargetUserName"),
            event_id=row.integer("EventID", "EventId"),
            process_id=row.integer("ProcessID", "ProcessId"),
            process_name=row.text("ProcessName", "Image"),
            source_ip=row.text("SrcIP", "SourceIP", "IpAddress"),
            destination_ip=row.text("DstIP", "DestinationIP"),
            file_path=row.text("FilePath", "Path"),
            raw_reference=raw_reference,
            attributes=row.raw,
        )
