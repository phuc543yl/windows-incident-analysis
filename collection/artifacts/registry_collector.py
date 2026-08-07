"""Save selected Windows Registry hives."""

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

ALLOWED_HIVES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}
DEFAULT_HIVES = ("SYSTEM", "SOFTWARE")


class RegistryCollector(BaseCollector):
    collector_id = "registry"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        configured = collector_options(options, self.collector_id)
        raw_hives = configured.get("hives", list(DEFAULT_HIVES))
        if not isinstance(raw_hives, list):
            raise ValueError("registry.hives phải là list.")
        hives = [
            str(hive).strip().upper()
            for hive in raw_hives
            if str(hive).strip()
        ]
        unknown = set(hives) - ALLOWED_HIVES
        if unknown:
            raise ValueError(f"Registry hive không hỗ trợ: {sorted(unknown)}")
        script = f"""
$Hives = {powershell_array(hives)}
$Copied = @()
foreach ($Hive in $Hives) {{
    $Target = Join-Path $Destination "$Hive.hiv"
    if (Test-Path -LiteralPath $Target) {{
        throw "Artifact đã tồn tại: $Target"
    }}
    $RegistryPath = if ($Hive -eq "DEFAULT") {{
        "HKU\\.DEFAULT"
    }} else {{
        "HKLM\\$Hive"
    }}
    & reg.exe save $RegistryPath $Target
    if ($LASTEXITCODE -ne 0) {{
        throw "reg.exe save $Hive exit code $LASTEXITCODE"
    }}
    $Copied += $Target
}}
[PSCustomObject]@{{
    files = @($Copied)
    warnings = @()
}} | ConvertTo-Json -Depth 4 -Compress
"""
        return run_export_script(
            client,
            destination,
            script,
            metadata={"hives": hives},
        )
