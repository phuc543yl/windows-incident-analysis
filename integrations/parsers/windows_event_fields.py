"""Read named Windows event data without changing the tool's original row."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from ipaddress import ip_address
from typing import Any

from integrations.parsers.base_parser import RowView

_MISSING = {"", "-", "n/a", "null", "none"}
# Only a labelled field following a separator starts a new value. Colons in
# IPv6 addresses, drive paths and command lines belong to the current value.
_DETAIL_FIELD = re.compile(r"(?:^|\s+[¦|]\s+)([A-Za-z][A-Za-z0-9_. ]*):\s*")
_CHANNELS = {
    "sec": "Security",
    "sys": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "pwsh": "Microsoft-Windows-PowerShell/Operational",
}


class WindowsEventFields:
    """Search payload/detail fields first, then explicit output columns."""

    def __init__(self, row: RowView, *containers: str) -> None:
        self.row = row
        self.extracted: dict[str, Any] = {}
        self._views = tuple(
            RowView(fields)
            for container in containers
            if (fields := _read_fields(row.get(container, default=None)))
        )
        for view in reversed(self._views):
            self.extracted.update(view.raw)
        self._views = (*self._views, row)

    def text(self, *aliases: str) -> str:
        for alias in aliases:
            for view in self._views:
                value = view.get(alias, default=None)
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    text = str(value).strip()
                    if text.casefold() not in _MISSING:
                        return text
        return ""

    def integer(self, *aliases: str) -> int | None:
        text = self.text(*aliases)
        try:
            # Decimal IDs may contain leading zeroes; Windows PIDs may be hex.
            return int(text, 16 if text.casefold().startswith("0x") else 10)
        except ValueError:
            return None

    def address(self, *aliases: str) -> str:
        for alias in aliases:
            for view in self._views:
                text = view.text(alias)
                try:
                    address = ip_address(text)
                except ValueError:
                    continue
                mapped = getattr(address, "ipv4_mapped", None)
                return str(mapped or address)
        return ""

    def user(self, event_id: int | None) -> str:
        if event_id in {4624, 4625}:
            name = self.text("TargetUserName", "TgtUser", "UserName", "User")
            domain = self.text("TargetDomainName", "TgtDomain")
            if name and domain and "\\" not in name and "@" not in name:
                return f"{domain}\\{name}"
            # SubjectUserName/UserId describe the event's reporter, not the
            # account being authenticated in 4624/4625.
            return name
        return self.text(
            "User", "UserName", "SubjectUserName", "SrcUser", "TargetUserName", "UserId"
        )

    def attributes(
        self, *, user: str, address: str, event_id: int | None
    ) -> dict[str, Any]:
        attributes = dict(self.row.raw)
        for name, value in self.extracted.items():
            attributes.setdefault(name, value)
        channel = self.text("Channel")
        attributes.update(
            target_user=user,
            source_ip=address,
            channel=_CHANNELS.get(channel.casefold(), channel),
            event_record_id=self.integer("EventRecordId", "RecordID"),
            source_event_file=self.text("SourceFile", "EvtxFile"),
        )
        logon_type = self.integer(
            "LogonType", *(("Type",) if event_id in {4624, 4625} else ())
        )
        if logon_type is not None:
            attributes["logon_type"] = logon_type
        command = self.text("CommandLine", "CmdLine")
        if command:
            attributes["command_line"] = command
        return attributes


def readable_text(value: Any) -> str:
    """Structured payloads stay in attributes, never in the summary cell."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if text.casefold() in _MISSING or text.startswith(("{", "[", "<")):
        return ""
    return text


def _read_fields(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith(("{", "[")):
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                return {}
        else:
            matches = tuple(_DETAIL_FIELD.finditer(text))
            return {
                match[1].strip(): text[
                    match.end() : matches[index + 1].start()
                    if index + 1 < len(matches)
                    else len(text)
                ].strip()
                for index, match in enumerate(matches)
            }
    fields: dict[str, Any] = {}
    _collect_fields(value, fields)
    return fields


def _collect_fields(value: Any, fields: dict[str, Any]) -> None:
    if isinstance(value, list):
        for item in value:
            _collect_fields(item, fields)
        return
    if not isinstance(value, Mapping):
        return
    keys = {str(key).casefold(): key for key in value}
    name_key = keys.get("@name")
    if name_key is not None:
        text_key = keys.get("#text")
        if text_key is not None:
            fields[str(value[name_key])] = value[text_key]
        return
    for name, item in value.items():
        if isinstance(item, (Mapping, list)):
            _collect_fields(item, fields)
        elif not str(name).startswith(("@", "#")):
            fields[str(name)] = item
