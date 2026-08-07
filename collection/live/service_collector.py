"""Collect Windows service configuration and state."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class ServiceCollector(BaseCollector):
    collector_id = "services"
    category = EvidenceCategory.LIVE
    output_filename = "services.json"

    SCRIPT = r"""
$ErrorActionPreference = "Stop"
$records = @(
    Get-CimInstance -ClassName Win32_Service |
    ForEach-Object {
        [PSCustomObject]@{
            name = $_.Name
            display_name = $_.DisplayName
            state = $_.State
            start_mode = $_.StartMode
            path_name = $_.PathName
            process_id = [int]$_.ProcessId
            start_name = $_.StartName
            service_type = $_.ServiceType
            exit_code = [int]$_.ExitCode
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
            raise ValueError("Service collector phải trả về JSON array.")
        return CollectorOutput(data=data)
