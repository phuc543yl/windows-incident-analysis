"""Hayabusa command adapter."""

from __future__ import annotations

from pathlib import Path

from common.enums import ArtifactType
from common.exceptions import ToolIntegrationError
from integrations.adapters.base_adapter import (
    BaseAdapter,
    ToolCommand,
    single_input,
)


class HayabusaAdapter(BaseAdapter):
    tool_id = "hayabusa"
    artifact_type = ArtifactType.EVENT_LOGS

    def build_command(self, input_paths: tuple[Path, ...], output_directory: Path) -> ToolCommand:
        source = single_input(self.tool_id, input_paths)
        if not source.is_dir():
            raise ToolIntegrationError(
                "Hayabusa yêu cầu thư mục chứa EVTX."
            )
        output = output_directory / "hayabusa.csv"
        return ToolCommand(
            arguments=(
                "csv-timeline",
                "-d",
                str(source),
                "-o",
                str(output),
                "--UTC",
            ),
            expected_output_globs=(output.name,),
        )
