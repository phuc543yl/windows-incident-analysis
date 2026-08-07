"""Validated Agent configuration loaded from config/agent.json."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from common.exceptions import ConfigurationError, JsonFileError
from common.json_utils import read_json_object
from common.paths import project_root

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HEADER_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


@dataclass(frozen=True, slots=True)
class AgentSettings:
    project: Path
    config_path: Path
    agent_id: str
    host: str
    port: int
    request_timeout_seconds: float
    max_concurrent_tasks: int
    authentication_enabled: bool
    token_header: str
    token_env: str
    token: str | None
    https_enabled: bool
    lab_mode_only: bool
    allowed_client_ips: tuple[str, ...]
    collector_allowlist: tuple[str, ...]
    max_bundle_size_bytes: int
    max_file_size_bytes: int
    command_timeout_seconds: float
    buffer_directory: Path
    delete_after_successful_transfer: bool
    retention_hours_on_failure: float
    audit_enabled: bool
    audit_file: Path
    redact_authentication_values: bool

    @classmethod
    def load(
        cls,
        config_path: str | Path,
        *,
        root: str | Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> "AgentSettings":
        path = Path(config_path).expanduser().resolve()
        project = project_root(
            root if root is not None else path.parent.parent
        )
        try:
            data = read_json_object(path)
        except JsonFileError as exc:
            raise ConfigurationError(str(exc)) from exc
        if data.get("schema_version") != 1:
            raise ConfigurationError(
                "agent.json có schema_version không hỗ trợ."
            )
        try:
            agent = _object(data, "agent")
            authentication = _object(data, "authentication")
            transport = _object(data, "transport")
            limits = _object(data, "limits")
            buffer = _object(data, "buffer")
            audit = _object(data, "audit")

            agent_id = _identifier(agent["agent_id"], "agent_id")
            host = _required_text(agent["host"], "host")
            port = _positive_int(agent["port"], "port")
            if port > 65535:
                raise ValueError("port phải nhỏ hơn hoặc bằng 65535.")
            timeout = _positive_number(
                agent["request_timeout_seconds"],
                "request_timeout_seconds",
            )
            max_tasks = _positive_int(
                agent["max_concurrent_tasks"],
                "max_concurrent_tasks",
            )
            auth_enabled = _boolean(
                authentication.get("enabled", True),
                "authentication.enabled",
            )
            token_header = _header_name(
                authentication.get(
                    "token_header",
                    "X-Agent-Token",
                )
            )
            token_env = _required_text(
                authentication.get("token_env", ""),
                "authentication.token_env",
            )
            allow_token = _boolean(
                authentication.get("allow_token_in_config", False),
                "authentication.allow_token_in_config",
            )
            configured_token = authentication.get("token")
            if configured_token and not allow_token:
                raise ValueError(
                    "Token không được lưu trực tiếp trong agent.json."
                )
            environment_values = (
                os.environ if environment is None else environment
            )
            token = (
                str(environment_values.get(token_env, "")).strip()
                if auth_enabled
                else None
            )
            if auth_enabled and not token:
                raise ValueError(
                    f"Thiếu biến môi trường xác thực Agent: {token_env}"
                )
            https_enabled = _boolean(
                transport.get("https_enabled", False),
                "transport.https_enabled",
            )
            lab_mode = _boolean(
                transport.get("lab_mode_only", True),
                "transport.lab_mode_only",
            )
            allowed_ips = _ip_list(
                transport.get("allowed_client_ips", ())
            )
            allowlist = _string_tuple(
                data.get("collector_allowlist"),
                "collector_allowlist",
            )
            max_bundle = _megabytes(
                limits["max_bundle_size_mb"],
                "max_bundle_size_mb",
            )
            max_file = _megabytes(
                limits["max_file_size_mb"],
                "max_file_size_mb",
            )
            command_timeout = _positive_number(
                limits["command_timeout_seconds"],
                "command_timeout_seconds",
            )
            buffer_directory = _relative_path(
                project,
                buffer["directory"],
                "buffer.directory",
            )
            delete_after = _boolean(
                buffer.get(
                    "delete_after_successful_transfer",
                    True,
                ),
                "buffer.delete_after_successful_transfer",
            )
            retention = _positive_number(
                buffer.get("retention_hours_on_failure", 24),
                "retention_hours_on_failure",
            )
            audit_enabled = _boolean(
                audit.get("enabled", True),
                "audit.enabled",
            )
            audit_file = _relative_path(
                project,
                audit["file"],
                "audit.file",
            )
            redact = _boolean(
                audit.get("redact_authentication_values", True),
                "audit.redact_authentication_values",
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"Cấu hình Agent không hợp lệ: {exc}"
            ) from exc

        if not https_enabled and not lab_mode:
            raise ConfigurationError(
                "Agent không dùng HTTPS chỉ được phép ở lab_mode_only."
            )
        return cls(
            project=project,
            config_path=path,
            agent_id=agent_id,
            host=host,
            port=port,
            request_timeout_seconds=timeout,
            max_concurrent_tasks=max_tasks,
            authentication_enabled=auth_enabled,
            token_header=token_header,
            token_env=token_env,
            token=token,
            https_enabled=https_enabled,
            lab_mode_only=lab_mode,
            allowed_client_ips=allowed_ips,
            collector_allowlist=allowlist,
            max_bundle_size_bytes=max_bundle,
            max_file_size_bytes=max_file,
            command_timeout_seconds=command_timeout,
            buffer_directory=buffer_directory,
            delete_after_successful_transfer=delete_after,
            retention_hours_on_failure=retention,
            audit_enabled=audit_enabled,
            audit_file=audit_file,
            redact_authentication_values=redact,
        )


def _object(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise TypeError(f"{key} phải là object.")
    return value


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} không được để trống.")
    return value.strip()


def _identifier(value: Any, field_name: str) -> str:
    text = _required_text(value, field_name)
    if not _IDENTIFIER_PATTERN.fullmatch(text):
        raise ValueError(f"{field_name} không hợp lệ.")
    return text


def _header_name(value: Any) -> str:
    text = _required_text(value, "token_header")
    if not _HEADER_PATTERN.fullmatch(text):
        raise ValueError("token_header không hợp lệ.")
    return text


def _positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{field_name} phải là số nguyên.")
    result = int(value)
    if result <= 0:
        raise ValueError(f"{field_name} phải là số nguyên dương.")
    return result


def _positive_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{field_name} phải là số.")
    result = float(value)
    if result <= 0:
        raise ValueError(f"{field_name} phải là số dương.")
    return result


def _boolean(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} phải là boolean.")
    return value


def _string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError(f"{field_name} phải là list.")
    result: list[str] = []
    for item in value:
        text = _identifier(item, f"{field_name} item").casefold()
        if text not in result:
            result.append(text)
    if not result:
        raise ValueError(f"{field_name} không được để trống.")
    return tuple(result)


def _ip_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("allowed_client_ips phải là list không rỗng.")
    result: list[str] = []
    for item in value:
        try:
            address = str(ipaddress.ip_address(str(item).strip()))
        except ValueError as exc:
            raise ValueError(
                "allowed_client_ips chứa IP không hợp lệ."
            ) from exc
        if address not in result:
            result.append(address)
    return tuple(result)


def _megabytes(value: Any, field_name: str) -> int:
    return int(_positive_number(value, field_name) * 1024 * 1024)


def _relative_path(
    project: Path,
    value: Any,
    field_name: str,
) -> Path:
    text = _required_text(value, field_name).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or ":" in text:
        raise ValueError(f"{field_name} phải là đường dẫn tương đối an toàn.")
    unresolved = project.joinpath(*path.parts)
    relative = unresolved.relative_to(project)
    current = project
    for part in relative.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ValueError(
                f"{field_name} không được đi qua symbolic link."
            )
    candidate = unresolved.resolve()
    try:
        candidate.relative_to(project)
    except ValueError as exc:
        raise ValueError(f"{field_name} nằm ngoài project.") from exc
    return candidate
