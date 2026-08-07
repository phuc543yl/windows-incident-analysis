"""Copy configured Windows Firewall text logs."""

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


class FirewallLogCollector(BaseCollector):
    collector_id = "firewall_logs"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        configured = collector_options(options, self.collector_id)
        raw_paths = configured.get(
            "paths",
            [
                r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
            ],
        )
        if (
            not isinstance(raw_paths, list)
            or not all(
                isinstance(item, str) and item.strip()
                for item in raw_paths
            )
        ):
            raise ValueError("firewall_logs.paths phải là list chuỗi.")
        sources = [item.strip() for item in raw_paths]
        script = f"""
$Sources = {powershell_array(sources)}
$Copied = @()
$Warnings = @()
foreach ($Source in $Sources) {{
    if (-not (Test-Path -LiteralPath $Source)) {{
        $Warnings += "Không tìm thấy: $Source"
        continue
    }}
    $Target = Join-Path $Destination (Split-Path -Leaf $Source)
    if (Test-Path -LiteralPath $Target) {{
        throw "Artifact đã tồn tại: $Target"
    }}
    Copy-Item -LiteralPath $Source -Destination $Target
    $Copied += $Target
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
            metadata={"source_paths": sources},
        )
