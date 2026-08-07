"""Base contract for invoking a DFIR tool and parsing its output."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from common.enums import ArtifactType, ToolRunStatus
from common.exceptions import ToolIntegrationError
from evidence.integrity_verifier import IntegrityVerifier
from integrations.parsers.base_parser import BaseParser
from integrations.tool_registry import ToolDefinition
from integrations.tool_runner import ToolRunner
from models.normalized_record import NormalizedRecord
from models.tool_result import ToolResult


@dataclass(frozen=True, slots=True)
class ToolCommand:
    arguments: tuple[str, ...]
    expected_output_globs: tuple[str, ...]


class BaseAdapter(ABC):
    tool_id: str
    artifact_type: ArtifactType

    def __init__(
        self,
        definition: ToolDefinition,
        runner: ToolRunner,
        parser: BaseParser,
    ) -> None:
        if definition.tool_id != self.tool_id:
            raise ValueError(
                f"Definition {definition.tool_id} không dành cho "
                f"adapter {self.tool_id}."
            )
        if not definition.supports(self.artifact_type):
            raise ValueError(
                f"Tool {definition.tool_id} không hỗ trợ "
                f"{self.artifact_type.value}."
            )
        if parser.tool_id != self.tool_id:
            raise ValueError(
                f"Parser {parser.tool_id} không dành cho "
                f"adapter {self.tool_id}."
            )
        self.definition = definition
        self.runner = runner
        self.parser = parser

    @abstractmethod
    def build_command(
        self,
        input_paths: tuple[Path, ...],
        output_directory: Path,
    ) -> ToolCommand:
        """Build arguments only; executable selection belongs to ToolRunner."""

    def run(
        self,
        *,
        case_id: str,
        input_paths: Iterable[str | Path],
        verify_integrity: bool = True,
    ) -> ToolResult:
        inputs = self._validate_inputs(input_paths)
        if verify_integrity:
            IntegrityVerifier(
                case_id,
                self.runner.repository.project,
            ).verify()
        output_directory = self.runner.create_run_directory(
            case_id,
            self.tool_id,
        )
        command = self.build_command(inputs, output_directory)
        return self.runner.run(
            case_id=case_id,
            tool=self.definition,
            arguments=command.arguments,
            output_directory=output_directory,
            expected_output_globs=command.expected_output_globs,
            metadata={
                "artifact_type": self.artifact_type.value,
                "input_paths": tuple(path.as_posix() for path in inputs),
            },
        )

    def parse(
        self,
        result: ToolResult,
        *,
        hostname: str = "",
    ) -> tuple[NormalizedRecord, ...]:
        if result.tool_id != self.tool_id:
            raise ToolIntegrationError(
                f"ToolResult {result.tool_id} không thuộc {self.tool_id}."
            )
        if result.status is not ToolRunStatus.SUCCEEDED:
            raise ToolIntegrationError(
                f"Không thể parse ToolResult có trạng thái "
                f"{result.status.value}."
            )
        case_paths = self.runner.repository.paths(result.case_id)
        records: list[NormalizedRecord] = []
        supported_suffixes = {".csv", ".json", ".jsonl"}
        for stored_path in result.output_files:
            candidate = case_paths.root.joinpath(
                *stored_path.replace("\\", "/").split("/")
            )
            if candidate.is_symlink():
                raise ToolIntegrationError(
                    f"Output không được là symbolic link: {stored_path}"
                )
            path = candidate.resolve()
            try:
                path.relative_to(case_paths.root)
            except ValueError as exc:
                raise ToolIntegrationError(
                    f"Output nằm ngoài Case: {stored_path}"
                ) from exc
            if path.suffix.casefold() not in supported_suffixes:
                continue
            records.extend(
                self.parser.parse(
                    path,
                    case_id=result.case_id,
                    hostname=hostname,
                    raw_reference=stored_path,
                )
            )
        return tuple(records)

    def _validate_inputs(
        self,
        values: Iterable[str | Path],
    ) -> tuple[Path, ...]:
        inputs: list[Path] = []
        for value in values:
            path = Path(value).expanduser()
            if path.is_symlink():
                raise ToolIntegrationError(
                    f"Input không được là symbolic link: {path}"
                )
            path = path.resolve()
            if not path.exists() or not (path.is_file() or path.is_dir()):
                raise ToolIntegrationError(
                    f"Không tìm thấy input cho {self.tool_id}: {path}"
                )
            inputs.append(path)
        if not inputs:
            raise ToolIntegrationError(
                f"{self.tool_id} cần ít nhất một input."
            )
        return tuple(inputs)


def single_input(
    tool_id: str,
    input_paths: tuple[Path, ...],
) -> Path:
    if len(input_paths) != 1:
        raise ToolIntegrationError(
            f"{tool_id} yêu cầu đúng một input."
        )
    return input_paths[0]


def file_or_directory_flag(path: Path) -> str:
    return "-d" if path.is_dir() else "-f"
