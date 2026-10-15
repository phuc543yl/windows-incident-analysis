"""Normalize EvtxECmd event rows."""

from __future__ import annotations

from common.enums import ArtifactType
from integrations.parsers.base_parser import BaseParser, RowView
from integrations.parsers.windows_event_fields import WindowsEventFields, readable_text
from models.normalized_record import NormalizedRecord


class EvtxECmdParser(BaseParser):
    tool_id = "evtxecmd"
    artifact_type = ArtifactType.EVENT_LOGS

    def parse_row(
        self, row: RowView, *, case_id: str, hostname: str, raw_reference: str
    ) -> NormalizedRecord:
        event_id = row.integer("EventId", "EventID")
        fields = WindowsEventFields(row, "Payload")
        provider = row.text("Provider", "ProviderName", default="Windows Event Log")
        user = fields.user(event_id)
        address = fields.address("IpAddress", "SrcIP", "SourceIP", "RemoteHost")
        summary = readable_text(row.get("MapDescription", "Description"))
        if not summary:
            summary = readable_text(row.get("Payload"))
        if not summary:
            summary = {4625: "Đăng nhập thất bại", 4624: "Đăng nhập thành công"}.get(
                event_id,
                f"{provider} event {event_id}" if event_id is not None else provider,
            )
        if event_id in {4624, 4625}:
            context = " · ".join(value for value in (user, address) if value)
            if context:
                summary = f"{summary} · {context}"
        return NormalizedRecord(
            case_id=case_id,
            source_type="evtxecmd_event",
            artifact_type=self.artifact_type,
            timestamp=self.timestamp(row, "TimeCreated", "Timestamp", "DateTime"),
            summary=summary,
            hostname=row.text("Computer", "ComputerName", default=hostname),
            user=user,
            event_id=event_id,
            process_id=fields.integer("NewProcessId", "ProcessId", "PID"),
            parent_process_id=fields.integer("ParentProcessId", "CreatorProcessId"),
            process_name=fields.text(
                "NewProcessName", "ProcessName", "Image", "ExecutableInfo"
            ),
            source_ip=address,
            destination_ip=fields.address("DestinationIp", "DstIP", "TgtIP"),
            file_path=fields.text("FilePath", "TargetFilename"),
            raw_reference=raw_reference,
            attributes=fields.attributes(user=user, address=address, event_id=event_id),
        )
