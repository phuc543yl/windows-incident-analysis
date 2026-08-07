"""Load and validate external DFIR tool definitions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from common.enums import ArtifactType
from common.exceptions import ConfigurationError
from common.json_utils import read_json_object
from common.paths import config_dir, project_root

_TOOL_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_OUTPUT_FORMATS = {"csv", "json", "jsonl"}


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    tool_id: str
    name: str
    enabled: bool
    required_for_mvp: bool
    adapter: str
    executable: str
    supported_artifacts: tuple[ArtifactType, ...]
    output_format: str
    timeout_seconds: float

    def __post_init__(self) -> None:
        tool_id = _normalized_id(self.tool_id, "tool_id")
        adapter = _normalized_id(self.adapter, "adapter")
        name = _required_text(self.name, "name")
        executable = _validate_executable(self.executable)
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled phải là boolean.")
        if not isinstance(self.required_for_mvp, bool):
            raise TypeError("required_for_mvp phải là boolean.")
        artifacts = tuple(
            item
            if isinstance(item, ArtifactType)
            else ArtifactType(str(item))
            for item in self.supported_artifacts
        )
        if not artifacts:
            raise ValueError("supported_artifacts không được để trống.")
        output_format = str(self.output_format).strip().lower()
        if output_format not in _OUTPUT_FORMATS:
            raise ValueError(
                f"output_format không hỗ trợ: {self.output_format}"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or float(self.timeout_seconds) <= 0
        ):
            raise ValueError("timeout_seconds phải là số dương.")

        object.__setattr__(self, "tool_id", tool_id)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "adapter", adapter)
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "supported_artifacts", artifacts)
        object.__setattr__(self, "output_format", output_format)
        object.__setattr__(
            self,
            "timeout_seconds",
            float(self.timeout_seconds),
        )

    def supports(self, artifact_type: ArtifactType | str) -> bool:
        normalized = (
            artifact_type
            if isinstance(artifact_type, ArtifactType)
            else ArtifactType(str(artifact_type))
        )
        return normalized in self.supported_artifacts

    def executable_path(self, root: str | Path) -> Path:
        return Path(root).expanduser().resolve().joinpath(
            *PurePosixPath(self.executable).parts
        )


class ToolRegistry:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        config_path: str | Path | None = None,
    ) -> None:
        self.project = project_root(root)
        self.config_path = (
            Path(config_path).expanduser().resolve()
            if config_path is not None
            else config_dir(self.project) / "tool_integrations.json"
        )
        self._tools = self._load()

    def get(
        self,
        tool_id: str,
        *,
        require_enabled: bool = False,
    ) -> ToolDefinition:
        normalized = _normalized_id(tool_id, "tool_id")
        try:
            definition = self._tools[normalized]
        except KeyError as exc:
            raise ConfigurationError(
                f"Không tìm thấy tool integration: {normalized}"
            ) from exc
        if require_enabled and not definition.enabled:
            raise ConfigurationError(
                f"Tool integration đang bị tắt: {normalized}"
            )
        return definition

    def list(
        self,
        *,
        enabled_only: bool = False,
    ) -> tuple[ToolDefinition, ...]:
        return tuple(
            self._tools[tool_id]
            for tool_id in sorted(self._tools)
            if not enabled_only or self._tools[tool_id].enabled
        )

    def for_artifact(
        self,
        artifact_type: ArtifactType | str,
        *,
        enabled_only: bool = True,
    ) -> tuple[ToolDefinition, ...]:
        return tuple(
            definition
            for definition in self.list(enabled_only=enabled_only)
            if definition.supports(artifact_type)
        )

    def _load(self) -> dict[str, ToolDefinition]:
        try:
            config = read_json_object(self.config_path)
        except Exception as exc:
            if isinstance(exc, ConfigurationError):
                raise
            raise ConfigurationError(str(exc)) from exc
        if config.get("schema_version") != 1:
            raise ConfigurationError(
                "tool_integrations.json có schema_version không hỗ trợ."
            )
        raw_tools = config.get("tools")
        if not isinstance(raw_tools, list):
            raise ConfigurationError(
                "tool_integrations.json phải có tools là list."
            )

        tools: dict[str, ToolDefinition] = {}
        for index, raw in enumerate(raw_tools):
            if not isinstance(raw, dict):
                raise ConfigurationError(
                    f"Tool tại vị trí {index} phải là object."
                )
            try:
                definition = ToolDefinition(
                    tool_id=raw["id"],
                    name=raw["name"],
                    enabled=raw["enabled"],
                    required_for_mvp=raw["required_for_mvp"],
                    adapter=raw["adapter"],
                    executable=raw["executable"],
                    supported_artifacts=tuple(
                        raw["supported_artifacts"]
                    ),
                    output_format=raw["output_format"],
                    timeout_seconds=raw["timeout_seconds"],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ConfigurationError(
                    f"Tool integration tại vị trí {index} không hợp lệ: "
                    f"{exc}"
                ) from exc
            if definition.tool_id in tools:
                raise ConfigurationError(
                    f"Trùng tool id: {definition.tool_id}"
                )
            tools[definition.tool_id] = definition
        return tools


def _normalized_id(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} phải là chuỗi.")
    normalized = value.strip().lower()
    if not _TOOL_ID_PATTERN.fullmatch(normalized):
        raise ValueError(f"{field_name} không hợp lệ: {value}")
    return normalized


def _required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} không được để trống.")
    return value.strip()


def _validate_executable(value: str) -> str:
    text = _required_text(value, "executable").replace("\\", "/")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or path.parts[0].casefold() != "tools"
        or ":" in path.parts[0]
    ):
        raise ValueError(
            "executable phải là đường dẫn tương đối an toàn trong tools/."
        )
    return path.as_posix()
