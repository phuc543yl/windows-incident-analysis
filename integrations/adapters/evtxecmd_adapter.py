"""EvtxECmd command adapter."""

from __future__ import annotations

from pathlib import Path

from common.enums import ArtifactType
from integrations.adapters.base_adapter import (
    BaseAdapter,
    ToolCommand,
    file_or_directory_flag,
    single_input,
)


class EvtxECmdAdapter(BaseAdapter):
    tool_id = "evtxecmd"
    artifact_type = ArtifactType.EVENT_LOGS

    def build_command(self, input_paths: tuple[Path, ...], output_directory: Path) -> ToolCommand:
        source = single_input(self.tool_id, input_paths)
        output_name = "evtxecmd.csv"
        return ToolCommand(
            arguments=(
                file_or_directory_flag(source),
                str(source),
                "--csv",
                str(output_directory),
                "--csvf",
                output_name,
            ),
            expected_output_globs=(output_name,),
        )
