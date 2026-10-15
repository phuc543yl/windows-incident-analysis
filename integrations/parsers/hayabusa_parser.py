"""Normalize Hayabusa timeline rows."""

from __future__ import annotations

import re
from datetime import datetime

from common.enums import ArtifactType
from common.exceptions import ToolIntegrationError
from common.time_utils import parse_timestamp
from integrations.parsers.base_parser import BaseParser, RowView
from integrations.parsers.windows_event_fields import WindowsEventFields, readable_text
from models.normalized_record import NormalizedRecord

_SPACED_OFFSET = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([+-]\d{2}:\d{2})$"
)


class HayabusaParser(BaseParser):
    tool_id = "hayabusa"
    artifact_type = ArtifactType.EVENT_LOGS

    def timestamp(self, row: RowView, *aliases: str) -> datetime:
        value = row.get(*aliases, default=None)
        match = (
            _SPACED_OFFSET.fullmatch(value.strip()) if isinstance(value, str) else None
        )
        if match:
            try:
                return parse_timestamp(f"{match[1]}{match[2]}")
            except ValueError as exc:
                raise ToolIntegrationError(f"Timestamp không hợp lệ: {value}") from exc
        return super().timestamp(row, *aliases)

    def parse_row(
        self, row: RowView, *, case_id: str, hostname: str, raw_reference: str
    ) -> NormalizedRecord:
        fields = WindowsEventFields(row, "AllFieldInfo", "ExtraFieldInfo", "Details")
        event_id = row.integer("EventID", "EventId")
        rule = (
            row.text("RuleTitle", "Title")
            or readable_text(row.get("Details"))
            or "Windows event"
        )
        user = fields.user(event_id)
        address = fields.address("IpAddress", "SrcIP", "SourceIP")
        return NormalizedRecord(
            case_id=case_id,
            source_type="hayabusa_event",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(row, "Timestamp", "Datetime", "TimeCreated"),
            summary=rule,
            hostname=row.text("Computer", "Hostname", default=hostname),
            user=user,
            event_id=event_id,
            process_id=fields.integer("NewProcessId", "ProcessID", "PID"),
            parent_process_id=fields.integer("ParentProcessId", "PPID"),
            process_name=fields.text(
                "NewProcessName", "ProcessName", "Image", "Proc", "Path"
            ),
            source_ip=address,
            destination_ip=fields.address("DestinationIP", "DstIP", "TgtIP"),
            file_path=fields.text("FilePath", "TargetFilename", "Path"),
            raw_reference=raw_reference,
            attributes=fields.attributes(user=user, address=address, event_id=event_id),
        )
