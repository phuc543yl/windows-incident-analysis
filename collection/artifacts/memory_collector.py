"""Import an explicitly acquired memory image as an optional artifact."""

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


class MemoryCollector(BaseCollector):
    collector_id = "memory"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        configured = collector_options(options, self.collector_id)
        image_path = configured.get("image_path")
        sources = [] if image_path is None else [str(image_path)]
        return copy_selected_files(
            client,
            destination,
            sources,
            empty_warning=(
                "Memory acquisition chưa bật; hãy cấu hình "
                "memory.image_path nếu đã có ảnh nhớ."
            ),
            metadata={
                "acquisition_performed": False,
                "source_paths": sources,
            },
        )
