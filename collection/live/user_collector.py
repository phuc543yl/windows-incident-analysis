"""Collect local Windows account information."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class UserCollector(BaseCollector):
    collector_id = "users"
    category = EvidenceCategory.LIVE
    output_filename = "users.json"

    SCRIPT = r"""
$ErrorActionPreference = "Stop"
$records = @(
    Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = True" |
    ForEach-Object {
        [PSCustomObject]@{
            name = $_.Name
            full_name = $_.FullName
            sid = $_.SID
            domain = $_.Domain
            disabled = [bool]$_.Disabled
            locked_out = [bool]$_.Lockout
            password_required = [bool]$_.PasswordRequired
            password_expires = [bool]$_.PasswordExpires
            status = $_.Status
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
            raise ValueError("User collector phải trả về JSON array.")
        return CollectorOutput(data=data)
