"""Copy analyst-selected files into the Case."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.artifacts._helpers import (
    collector_options,
    copy_selected_files,
)
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory


class FileCollector(BaseCollector):
    collector_id = "files"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        configured = collector_options(options, self.collector_id)
        raw_paths = configured.get("paths", [])
        if not isinstance(raw_paths, list):
            raise ValueError("files.paths phải là list.")
        sources = [str(path) for path in raw_paths]
        return copy_selected_files(
            client,
            destination,
            sources,
            empty_warning=(
                "Chưa cấu hình files.paths; không thu tệp tùy chọn."
            ),
            metadata={"source_paths": sources},
        )
