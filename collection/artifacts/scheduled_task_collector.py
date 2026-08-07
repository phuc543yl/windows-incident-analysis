"""Copy Scheduled Task definitions while preserving relative paths."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.artifacts._helpers import run_export_script
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class ScheduledTaskCollector(BaseCollector):
    collector_id = "scheduled_tasks"
    category = EvidenceCategory.RAW_ARTIFACT

    SCRIPT = r"""
$SourceRoot = Join-Path $env:SystemRoot "System32\Tasks"
$Copied = @()
$Warnings = @()
if (-not (Test-Path -LiteralPath $SourceRoot)) {
    $Warnings += "Không tìm thấy thư mục Scheduled Tasks."
} else {
    Get-ChildItem -LiteralPath $SourceRoot -File -Recurse |
    ForEach-Object {
        $Relative = $_.FullName.Substring($SourceRoot.Length).TrimStart('\')
        $Target = Join-Path $Destination $Relative
        if (Test-Path -LiteralPath $Target) {
            throw "Artifact đã tồn tại: $Target"
        }
        New-Item -ItemType Directory -Path (
            Split-Path -Parent $Target
        ) -Force | Out-Null
        Copy-Item -LiteralPath $_.FullName -Destination $Target
        $Copied += $Target
    }
}
[PSCustomObject]@{
    files = @($Copied)
    warnings = @($Warnings)
} | ConvertTo-Json -Depth 4 -Compress
"""

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        del options
        return run_export_script(client, destination, self.SCRIPT)
