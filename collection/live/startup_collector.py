"""Collect Windows startup commands."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class StartupCollector(BaseCollector):
    collector_id = "startup"
    category = EvidenceCategory.LIVE
    output_filename = "startup.json"

    SCRIPT = r"""
$ErrorActionPreference = "Stop"
$records = @(
    Get-CimInstance -ClassName Win32_StartupCommand |
    ForEach-Object {
        [PSCustomObject]@{
            name = $_.Name
            command = $_.Command
            location = $_.Location
            user = $_.User
            caption = $_.Caption
            description = $_.Description
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
            raise ValueError("Startup collector phải trả về JSON array.")
        return CollectorOutput(data=data)
