"""Normalize EvtxECmd event rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from models.normalized_record import NormalizedRecord


class EvtxECmdParser(BaseParser):
    tool_id = "evtxecmd"
    artifact_type = ArtifactType.EVENT_LOGS

    def parse_row(self, row: RowView, *, case_id: str, hostname: str, raw_reference: str) -> NormalizedRecord:
        event_id = row.integer("EventId", "EventID")
        provider = row.text("Provider", "ProviderName", default="Windows Event Log")
        summary = row.text("Payload", "MapDescription", "Description")
        if not summary:
            summary = f"{provider} event {event_id}" if event_id is not None else provider
        return NormalizedRecord(
            case_id=case_id,
            source_type="evtxecmd_event",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(row, "TimeCreated", "Timestamp", "DateTime"),
            summary=summary,
            hostname=row.text("Computer", "ComputerName", default=hostname),
            user=row.text("UserId", "UserName", "User"),
            event_id=event_id,
            process_id=row.integer("ProcessId", "ProcessID"),
            raw_reference=raw_reference,
            attributes=row.raw,
        )
