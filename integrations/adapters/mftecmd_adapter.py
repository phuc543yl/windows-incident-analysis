"""MFTECmd command adapter."""

from __future__ import annotations

from pathlib import Path

from common.enums import ArtifactType
from common.exceptions import ToolIntegrationError
from integrations.adapters.base_adapter import (
    BaseAdapter,
    ToolCommand,
    single_input,
)


class MFTECmdAdapter(BaseAdapter):
    tool_id = "mftecmd"
    artifact_type = ArtifactType.MFT

    def build_command(self, input_paths: tuple[Path, ...], output_directory: Path) -> ToolCommand:
        source = single_input(self.tool_id, input_paths)
        if not source.is_file():
            raise ToolIntegrationError("MFTECmd yêu cầu một file $MFT.")
        output_name = "mftecmd.csv"
        return ToolCommand(
            arguments=(
                "-f",
                str(source),
                "--csv",
                str(output_directory),
                "--csvf",
                output_name,
            ),
            expected_output_globs=(output_name,),
        )
