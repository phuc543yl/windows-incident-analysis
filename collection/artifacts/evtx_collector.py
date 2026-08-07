"""Export selected Windows Event Log channels to EVTX."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.artifacts._helpers import (
    collector_options,
    powershell_array,
    run_export_script,
)
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory

DEFAULT_EVENT_LOGS = (
    "Security",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
)


class Channel:
    pass


class EvtxCollector(BaseCollector):
    collector_id = "event_logs"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        configured = collector_options(options, self.collector_id)
        logs = configured.get("channels", list(DEFAULT_EVENT_LOGS))
        if (
            not isinstance(logs, list)
            or not all(isinstance(item, str) and item.strip() for item in logs)
        ):
            raise ValueError("event_logs.channels phải là list chuỗi.")
        channels = [item.strip() for item in logs]
        script = f"""
$Channels = {powershell_array(channels)}
$Copied = @()
$Warnings = @()
foreach ($Channel in $Channels) {{
    $SafeName = ($Channel -replace '[\\\\/:*?"<>|]', '_') + '.evtx'
    $Target = Join-Path $Destination $SafeName
    if (Test-Path -LiteralPath $Target) {{
        throw "Artifact đã tồn tại: $Target"
    }}
    try {{
        & wevtutil.exe epl $Channel $Target
        if ($LASTEXITCODE -ne 0) {{
            throw "wevtutil exit code $LASTEXITCODE"
        }}
        $Copied += $Target
    }} catch {{
        $Warnings += "${Channel}: $($_.Exception.Message)"
    }}
}}
[PSCustomObject]@{{
    files = @($Copied)
    warnings = @($Warnings)
}} | ConvertTo-Json -Depth 4 -Compress
"""
        return run_export_script(
            client,
            destination,
            script,
            metadata={"channels": channels},
        )
