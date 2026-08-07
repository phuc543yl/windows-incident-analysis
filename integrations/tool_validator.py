"""Validate configured DFIR executables before execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from common.exceptions import ToolIntegrationError
from common.paths import tools_dir
from integrations.tool_registry import ToolDefinition, ToolRegistry


@dataclass(frozen=True, slots=True)
class ToolValidation:
    tool_id: str
    executable_path: Path
    enabled: bool
    available: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "executable_path": self.executable_path.as_posix(),
            "enabled": self.enabled,
            "available": self.available,
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


class ToolValidator:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def validate(
        self,
        definition: ToolDefinition | str,
    ) -> ToolValidation:
        tool = (
            self.registry.get(definition)
            if isinstance(definition, str)
            else definition
        )
        executable_path = tool.executable_path(self.registry.project)
        errors: list[str] = []
        warnings: list[str] = []
        try:
            executable_path.relative_to(
                tools_dir(self.registry.project)
            )
        except ValueError:
            errors.append("Executable nằm ngoài thư mục tools.")
        if executable_path.is_symlink():
            errors.append("Executable không được là symbolic link.")
        if not executable_path.exists():
            errors.append("Không tìm thấy executable.")
        elif not executable_path.is_file():
            errors.append("Executable path không phải file.")
        if not tool.enabled:
            warnings.append("Tool đang bị tắt trong cấu hình.")
        return ToolValidation(
            tool_id=tool.tool_id,
            executable_path=executable_path,
            enabled=tool.enabled,
            available=executable_path.is_file() and not executable_path.is_symlink(),
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    def validate_all(self) -> tuple[ToolValidation, ...]:
        return tuple(
            self.validate(definition)
            for definition in self.registry.list()
        )

    def require_available(
        self,
        definition: ToolDefinition | str,
    ) -> Path:
        tool = (
            self.registry.get(definition)
            if isinstance(definition, str)
            else definition
        )
        if not tool.enabled:
            raise ToolIntegrationError(
                f"Tool integration đang bị tắt: {tool.tool_id}"
            )
        result = self.validate(tool)
        if not result.valid or not result.available:
            detail = "; ".join(result.errors) or "không khả dụng"
            raise ToolIntegrationError(
                f"Tool {tool.tool_id} không khả dụng: {detail}"
            )
        return result.executable_path
