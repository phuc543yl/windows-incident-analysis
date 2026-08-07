"""Copy Windows Prefetch files."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.artifacts._helpers import run_export_script
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class PrefetchCollector(BaseCollector):
    collector_id = "prefetch"
    category = EvidenceCategory.RAW_ARTIFACT

    SCRIPT = r"""
$SourceRoot = Join-Path $env:SystemRoot "Prefetch"
$Copied = @()
$Warnings = @()
if (-not (Test-Path -LiteralPath $SourceRoot)) {
    $Warnings += "Không tìm thấy thư mục Prefetch."
} else {
    Get-ChildItem -LiteralPath $SourceRoot -Filter "*.pf" -File |
    ForEach-Object {
        $Target = Join-Path $Destination $_.Name
        if (Test-Path -LiteralPath $Target) {
            throw "Artifact đã tồn tại: $Target"
        }
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
