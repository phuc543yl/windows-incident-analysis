"""Local Windows client for PowerShell execution and artifact copying."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from clients.base_client import BaseClient, CommandResult
from common.enums import OperationMode
from common.exceptions import (
    ClientConnectionError,
    ClientError,
    CommandExecutionError,
)
from common.time_utils import utc_now

_POWERSHELL_ARGUMENTS = (
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
)

_UTF8_PREAMBLE = (
    "$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)\n"
    "[Console]::OutputEncoding = $Utf8NoBom\n"
    "$OutputEncoding = $Utf8NoBom\n"
)


class LocalClient(BaseClient):
    """Execute trusted collector scripts on the current Windows endpoint."""

    mode = OperationMode.LOCAL

    def __init__(
        self,
        powershell_executable: str | Path | None = None,
        *,
        timeout_seconds: int | float = 120,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds)
        self.powershell_executable = self._resolve_executable(
            powershell_executable
        )

    def health_check(self) -> dict[str, Any]:
        executable = self.powershell_executable
        candidate = Path(executable).expanduser()
        available = (
            candidate.is_file()
            if candidate.is_absolute() or candidate.parent != Path(".")
            else shutil.which(executable) is not None
        )
        return {
            "mode": self.mode.value,
            "available": available,
            "powershell_executable": executable,
        }

    def execute_powershell(
        self,
        script: str,
        *,
        timeout_seconds: int | float | None = None,
    ) -> CommandResult:
        if not isinstance(script, str) or not script.strip():
            raise ValueError("PowerShell script không được để trống.")

        timeout = (
            self.timeout_seconds
            if timeout_seconds is None
            else self.validate_timeout(timeout_seconds)
        )

        full_script = f"{_UTF8_PREAMBLE}{script}"

        encoded_command = base64.b64encode(
            full_script.encode("utf-16-le")
        ).decode("ascii")

        process_arguments = (
            *_POWERSHELL_ARGUMENTS,
            encoded_command,
        )
        command = [
            self.powershell_executable,
            *process_arguments,
        ]
        started_at = utc_now()

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise ClientConnectionError(
                "Không tìm thấy PowerShell. Hãy cài PowerShell hoặc truyền "
                "đúng powershell_executable."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandExecutionError(
                f"PowerShell vượt quá timeout {timeout:g} giây."
            ) from exc
        except OSError as exc:
            raise ClientConnectionError(
                f"Không thể khởi chạy PowerShell: {exc}"
            ) from exc

        result = CommandResult(
            executable=self.powershell_executable,
            arguments=(
                *_POWERSHELL_ARGUMENTS,
                "<encoded-script>",
            ),
            return_code=completed.returncode,
            stdout=(completed.stdout or "").lstrip("\ufeff").strip(),
            stderr=(completed.stderr or "").lstrip("\ufeff").strip(),
            started_at=started_at,
            finished_at=utc_now(),
        )

        if not result.success:
            message = _compact_error(result.stderr or result.stdout)
            raise CommandExecutionError(
                f"PowerShell kết thúc với mã {result.return_code}: {message}"
            )

        return result

    def execute_powershell_json(
        self,
        script: str,
        *,
        timeout_seconds: int | float | None = None,
    ) -> dict[str, Any] | list[Any]:
        result = self.execute_powershell(
            script,
            timeout_seconds=timeout_seconds,
        )

        if not result.stdout:
            detail = _compact_error(result.stderr)
            raise CommandExecutionError(
                "PowerShell không trả về dữ liệu JSON. "
                f"STDERR: {detail}"
            )

        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            preview = _compact_error(result.stdout, limit=300)
            raise CommandExecutionError(
                "PowerShell trả về JSON không hợp lệ "
                f"tại dòng {exc.lineno}, cột {exc.colno}. "
                f"Nội dung: {preview}"
            ) from exc

        if not isinstance(value, (dict, list)):
            raise CommandExecutionError(
                "Kết quả PowerShell JSON phải là object hoặc array."
            )

        return value

    def copy_file(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        source_path = Path(source).expanduser().resolve()
        destination_path = Path(destination).expanduser().resolve()

        if not source_path.is_file():
            raise ClientError(
                f"Không tìm thấy artifact nguồn: {source_path}"
            )

        if destination_path.exists() and not overwrite:
            raise FileExistsError(
                f"Artifact đích đã tồn tại: {destination_path}"
            )

        try:
            destination_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            shutil.copy2(source_path, destination_path)
        except OSError as exc:
            raise ClientError(
                f"Không thể sao chép artifact tới "
                f"{destination_path}: {exc}"
            ) from exc

        return destination_path

    @staticmethod
    def _resolve_executable(
        value: str | Path | None,
    ) -> str:
        if value is not None:
            text = str(value).strip()
            if not text:
                raise ValueError(
                    "powershell_executable không được để trống."
                )
            return text

        for name in ("powershell.exe", "pwsh.exe", "pwsh"):
            resolved = shutil.which(name)
            if resolved:
                return resolved

        return "powershell.exe"


def _compact_error(
    value: str,
    limit: int = 1000,
) -> str:
    compact = " ".join(value.split())

    if not compact:
        return "không có thông báo lỗi"

    if len(compact) <= limit:
        return compact

    return f"{compact[:limit]}..."