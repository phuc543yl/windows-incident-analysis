"""Run configured DFIR executables without invoking a command shell."""

from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from case_management.case_repository import CaseRepository
from common.enums import ToolRunStatus
from common.exceptions import ToolIntegrationError
from common.json_utils import append_jsonl
from common.time_utils import filename_timestamp, utc_now
from integrations.tool_registry import ToolDefinition, ToolRegistry
from integrations.tool_validator import ToolValidator
from models import new_id
from models.tool_result import ToolResult


class ToolRunner:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        registry: ToolRegistry | None = None,
        validator: ToolValidator | None = None,
    ) -> None:
        self.repository = CaseRepository(root)
        self.registry = registry or ToolRegistry(self.repository.project)
        self.validator = validator or ToolValidator(self.registry)

    def create_run_directory(
        self,
        case_id: str,
        tool_id: str,
    ) -> Path:
        self.repository.require_open(case_id)
        definition = self.registry.get(tool_id, require_enabled=True)
        paths = self.repository.paths(case_id)
        run_id = (
            f"{filename_timestamp()}_"
            f"{new_id('RUN').split('-', maxsplit=1)[1][:12]}"
        )
        output = paths.tool_outputs / definition.tool_id / run_id
        output.mkdir(parents=True, exist_ok=False)
        return output

    def run(
        self,
        *,
        case_id: str,
        tool: ToolDefinition | str,
        arguments: tuple[str, ...] | list[str],
        output_directory: str | Path,
        expected_output_globs: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> ToolResult:
        case = self.repository.require_open(case_id)
        definition = (
            self.registry.get(tool, require_enabled=True)
            if isinstance(tool, str)
            else tool
        )
        if not definition.enabled:
            raise ToolIntegrationError(
                f"Tool integration đang bị tắt: {definition.tool_id}"
            )
        executable = self.validator.require_available(definition)
        output_dir = self._validate_output_directory(
            case.case_id,
            output_directory,
        )
        normalized_arguments = _validate_arguments(arguments)
        normalized_globs = _validate_globs(expected_output_globs)
        command = (str(executable), *normalized_arguments)
        started_at = utc_now()
        stdout = ""
        stderr = ""
        exit_code: int | None = None
        status = ToolRunStatus.RUNNING
        error_message = ""

        try:
            completed = subprocess.run(
                list(command),
                cwd=self.repository.project,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=definition.timeout_seconds,
                check=False,
                shell=False,
            )
            stdout = (completed.stdout or "").lstrip("\ufeff")
            stderr = (completed.stderr or "").lstrip("\ufeff")
            exit_code = completed.returncode
            if exit_code == 0:
                status = ToolRunStatus.SUCCEEDED
            else:
                status = ToolRunStatus.FAILED
                error_message = _compact_error(stderr or stdout)
        except subprocess.TimeoutExpired as exc:
            status = ToolRunStatus.TIMED_OUT
            stdout = _timeout_text(exc.stdout)
            stderr = _timeout_text(exc.stderr)
            error_message = (
                f"Tool vượt quá timeout "
                f"{definition.timeout_seconds:g} giây."
            )
        except OSError as exc:
            status = ToolRunStatus.FAILED
            error_message = f"Không thể chạy tool: {exc}"

        stdout_path = output_dir / "stdout.txt"
        stderr_path = output_dir / "stderr.txt"
        stdout_path.write_text(stdout, encoding="utf-8")
        stderr_path.write_text(stderr, encoding="utf-8")
        output_files = self._discover_outputs(
            output_dir,
            normalized_globs,
        )
        if (
            status is ToolRunStatus.SUCCEEDED
            and normalized_globs
            and not output_files
        ):
            status = ToolRunStatus.FAILED
            error_message = "Tool không tạo output như mong đợi."

        paths = self.repository.paths(case.case_id)
        result = ToolResult(
            case_id=case.case_id,
            tool_id=definition.tool_id,
            status=status,
            started_at=started_at,
            finished_at=utc_now(),
            exit_code=exit_code,
            command=command,
            output_files=tuple(
                path.relative_to(paths.root).as_posix()
                for path in output_files
            ),
            stdout_path=stdout_path.relative_to(paths.root).as_posix(),
            stderr_path=stderr_path.relative_to(paths.root).as_posix(),
            error_message=error_message,
            metadata=dict(metadata or {}),
        )
        append_jsonl(paths.tool_runs_log, result.to_dict())
        return result

    def _validate_output_directory(
        self,
        case_id: str,
        value: str | Path,
    ) -> Path:
        paths = self.repository.paths(case_id)
        candidate = Path(value).expanduser()
        if candidate.is_symlink():
            raise ToolIntegrationError(
                "Tool output directory không được là symbolic link."
            )
        output_dir = candidate.resolve()
        try:
            output_dir.relative_to(paths.tool_outputs)
        except ValueError as exc:
            raise ToolIntegrationError(
                "Tool output directory phải nằm trong analysis/tool_outputs."
            ) from exc
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _discover_outputs(
        self,
        output_dir: Path,
        patterns: tuple[str, ...],
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []
        if patterns:
            for pattern in patterns:
                candidates.extend(output_dir.glob(pattern))
        else:
            candidates.extend(output_dir.rglob("*"))
        ignored = {"stdout.txt", "stderr.txt"}
        unique: dict[str, Path] = {}
        for path in candidates:
            if path.name in ignored or not path.is_file():
                continue
            if path.is_symlink():
                raise ToolIntegrationError(
                    f"Tool output không được là symbolic link: {path}"
                )
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(output_dir)
            except ValueError as exc:
                raise ToolIntegrationError(
                    f"Tool output nằm ngoài run directory: {path}"
                ) from exc
            unique[relative.as_posix()] = resolved
        return tuple(
            unique[key]
            for key in sorted(unique, key=str.casefold)
        )


def _validate_arguments(
    values: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise TypeError("arguments phải là tuple hoặc list.")
    result: list[str] = []
    for value in values:
        text = str(value)
        if not text or "\x00" in text:
            raise ValueError("Tool argument không hợp lệ.")
        result.append(text)
    return tuple(result)


def _validate_globs(values: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        path = PurePosixPath(str(value).replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"Output glob không an toàn: {value}")
        result.append(path.as_posix())
    return tuple(result)


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _compact_error(value: str, limit: int = 1000) -> str:
    text = " ".join(value.split())
    if not text:
        return "Tool kết thúc nhưng không có thông báo lỗi."
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."
