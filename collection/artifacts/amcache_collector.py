"""Copy the Windows Amcache registry hive."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.artifacts._helpers import run_export_script
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class AmcacheCollector(BaseCollector):
    collector_id = "amcache"
    category = EvidenceCategory.RAW_ARTIFACT

    SCRIPT = r"""
$Source = Join-Path $env:SystemRoot "AppCompat\Programs\Amcache.hve"
$Target = Join-Path $Destination "Amcache.hve"
$Copied = @()
$Warnings = @()
if (-not (Test-Path -LiteralPath $Source)) {
    $Warnings += "Không tìm thấy Amcache.hve."
} elseif (Test-Path -LiteralPath $Target) {
    throw "Artifact đã tồn tại: $Target"
} else {
    Copy-Item -LiteralPath $Source -Destination $Target
    $Copied += $Target
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
