"""AmcacheParser command adapter."""

from __future__ import annotations

from pathlib import Path

from common.enums import ArtifactType
from common.exceptions import ToolIntegrationError
from integrations.adapters.base_adapter import (
    BaseAdapter,
    ToolCommand,
    single_input,
)


class AmcacheParserAdapter(BaseAdapter):
    tool_id = "amcacheparser"
    artifact_type = ArtifactType.AMCACHE

    def build_command(self, input_paths: tuple[Path, ...], output_directory: Path) -> ToolCommand:
        source = single_input(self.tool_id, input_paths)
        if not source.is_file():
            raise ToolIntegrationError(
                "AmcacheParser yêu cầu file Amcache.hve."
            )
        output_name = "amcache.csv"
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
