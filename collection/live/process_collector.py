"""Collect running processes and command lines."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class ProcessCollector(BaseCollector):
    collector_id = "processes"
    category = EvidenceCategory.LIVE
    output_filename = "processes.json"

    SCRIPT = r"""
$ErrorActionPreference = "Stop"
$records = @(
    Get-CimInstance -ClassName Win32_Process |
    ForEach-Object {
        $owner = $null
        try {
            $ownerResult = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
            if ($ownerResult.ReturnValue -eq 0) {
                $owner = "$($ownerResult.Domain)\$($ownerResult.User)"
            }
        } catch {}
        [PSCustomObject]@{
            name = $_.Name
            pid = [int]$_.ProcessId
            parent_pid = [int]$_.ParentProcessId
            executable_path = $_.ExecutablePath
            command_line = $_.CommandLine
            creation_date = $_.CreationDate
            owner = $owner
            session_id = [int]$_.SessionId
        }
    }
)
ConvertTo-Json -InputObject @($records) -Depth 4 -Compress
"""

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        del destination, options
        data = client.execute_powershell_json(self.SCRIPT)
        if not isinstance(data, list):
            raise ValueError("Process collector phải trả về JSON array.")
        return CollectorOutput(data=data)
