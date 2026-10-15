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

    def build_command(
        self, input_paths: tuple[Path, ...], output_directory: Path
    ) -> ToolCommand:
        source = single_input(self.tool_id, input_paths)
        if not source.is_dir():
            raise ToolIntegrationError("Hayabusa yêu cầu thư mục chứa EVTX.")
        output = output_directory / "hayabusa.csv"
        return ToolCommand(
            arguments=(
                "csv-timeline",
                "-d",
                str(source),
                "-o",
                str(output),
                "--UTC",
                # The GUI captures stdout/stderr without an interactive terminal.
                "--no-wizard",
                "--no-color",
                # Retain the native record ID and EVTX path for cross-tool counts.
                "--profile",
                "verbose",
            ),
            expected_output_globs=(output.name,),
        )
