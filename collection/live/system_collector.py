"""Collect operating-system and hardware summary."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class SystemCollector(BaseCollector):
    collector_id = "system"
    category = EvidenceCategory.LIVE
    output_filename = "system.json"

    SCRIPT = r"""
$ErrorActionPreference = "Stop"
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$processors = @(
    Get-CimInstance -ClassName Win32_Processor |
    ForEach-Object {
        [PSCustomObject]@{
            name = $_.Name
            manufacturer = $_.Manufacturer
            cores = $_.NumberOfCores
            logical_processors = $_.NumberOfLogicalProcessors
            max_clock_mhz = $_.MaxClockSpeed
        }
    }
)
$disks = @(
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" |
    ForEach-Object {
        [PSCustomObject]@{
            device_id = $_.DeviceID
            filesystem = $_.FileSystem
            size_bytes = [int64]$_.Size
            free_bytes = [int64]$_.FreeSpace
        }
    }
)
$record = [PSCustomObject]@{
    hostname = $env:COMPUTERNAME
    os_name = $os.Caption
    os_version = $os.Version
    os_build = $os.BuildNumber
    architecture = $os.OSArchitecture
    install_date = $os.InstallDate
    last_boot_time = $os.LastBootUpTime
    current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    domain = $computer.Domain
    manufacturer = $computer.Manufacturer
    model = $computer.Model
    memory_bytes = [int64]$computer.TotalPhysicalMemory
    processors = $processors
    disks = $disks
}
ConvertTo-Json -InputObject $record -Depth 6 -Compress
"""

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        del destination, options
        data = client.execute_powershell_json(self.SCRIPT)
        if not isinstance(data, dict):
            raise ValueError("System collector phải trả về JSON object.")
        return CollectorOutput(data=data)
