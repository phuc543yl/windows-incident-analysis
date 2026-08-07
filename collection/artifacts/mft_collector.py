"""Copy the NTFS Master File Table from a selected system drive."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.artifacts._helpers import (
    collector_options,
    powershell_quote,
    run_export_script,
)
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class MftCollector(BaseCollector):
    collector_id = "mft"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        configured = collector_options(options, self.collector_id)
        drive = str(configured.get("system_drive", "C:")).strip().upper()
        if not re.fullmatch(r"[A-Z]:", drive):
            raise ValueError("mft.system_drive phải có dạng C:.")
        source = rf"\\?\{drive}\$MFT"
        script = f"""
$Source = {powershell_quote(source)}
$Target = Join-Path $Destination '$MFT'
if (Test-Path -LiteralPath $Target) {{
    throw "Artifact đã tồn tại: $Target"
}}
Copy-Item -LiteralPath $Source -Destination $Target
[PSCustomObject]@{{
    files = @($Target)
    warnings = @()
}} | ConvertTo-Json -Depth 4 -Compress
"""
        return run_export_script(
            client,
            destination,
            script,
            metadata={"source": source},
        )
