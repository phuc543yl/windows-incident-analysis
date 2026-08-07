"""Collect current TCP and UDP endpoints."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class NetworkCollector(BaseCollector):
    collector_id = "network"
    category = EvidenceCategory.LIVE
    output_filename = "network.json"

    SCRIPT = r"""
$ErrorActionPreference = "Stop"
$records = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $records += @(
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
        ForEach-Object {
            [PSCustomObject]@{
                protocol = "tcp"
                local_address = $_.LocalAddress
                local_port = [int]$_.LocalPort
                remote_address = $_.RemoteAddress
                remote_port = [int]$_.RemotePort
                state = [string]$_.State
                pid = [int]$_.OwningProcess
            }
        }
    )
}
if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
    $records += @(
        Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        ForEach-Object {
            [PSCustomObject]@{
                protocol = "udp"
                local_address = $_.LocalAddress
                local_port = [int]$_.LocalPort
                remote_address = $null
                remote_port = $null
                state = $null
                pid = [int]$_.OwningProcess
            }
        }
    )
}
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
            raise ValueError("Network collector phải trả về JSON array.")
        return CollectorOutput(data=data)
