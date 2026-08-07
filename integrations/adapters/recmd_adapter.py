"""RECmd command adapter."""

from __future__ import annotations

from pathlib import Path

from common.enums import ArtifactType
from integrations.adapters.base_adapter import (
    BaseAdapter,
    ToolCommand,
    file_or_directory_flag,
    single_input,
)


class RECmdAdapter(BaseAdapter):
    tool_id = "recmd"
    artifact_type = ArtifactType.REGISTRY

    def build_command(self, input_paths: tuple[Path, ...], output_directory: Path) -> ToolCommand:
        source = single_input(self.tool_id, input_paths)
        output_name = "recmd.csv"
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
