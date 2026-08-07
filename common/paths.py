"""Safe resolution of project-level configuration and runtime paths."""

from __future__ import annotations

import os
from pathlib import Path

from common.constants import (
    AGENT_BUFFER_DIRECTORY_NAME,
    CASES_DIRECTORY_NAME,
    CONFIG_DIRECTORY_NAME,
    LOGS_DIRECTORY_NAME,
    RUNTIME_DIRECTORY_NAME,
    TOOLS_DIRECTORY_NAME,
)
from common.exceptions import UnsafePathError

PROJECT_ROOT_ENV = "WINDOWS_FORENSIC_ROOT"


def project_root(explicit_root: str | Path | None = None) -> Path:
    """Return the project root.

    Precedence: explicit argument, ``WINDOWS_FORENSIC_ROOT`` environment
    variable, then the parent directory containing this ``common`` package.
    """
    if explicit_root is not None:
        return Path(explicit_root).expanduser().resolve()
    environment_root = os.getenv(PROJECT_ROOT_ENV)
    if environment_root:
        return Path(environment_root).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def config_dir(root: str | Path | None = None) -> Path:
    return safe_join(project_root(root), CONFIG_DIRECTORY_NAME)


def tools_dir(root: str | Path | None = None) -> Path:
    return safe_join(project_root(root), TOOLS_DIRECTORY_NAME)


def runtime_dir(root: str | Path | None = None) -> Path:
    return safe_join(project_root(root), RUNTIME_DIRECTORY_NAME)


def cases_dir(root: str | Path | None = None) -> Path:
    return safe_join(runtime_dir(root), CASES_DIRECTORY_NAME)


def agent_buffer_dir(root: str | Path | None = None) -> Path:
    return safe_join(runtime_dir(root), AGENT_BUFFER_DIRECTORY_NAME)


def logs_dir(root: str | Path | None = None) -> Path:
    return safe_join(runtime_dir(root), LOGS_DIRECTORY_NAME)


def ensure_base_directories(root: str | Path | None = None) -> dict[str, Path]:
    """Create non-Case base directories and return their resolved paths."""
    directories = {
        "config": config_dir(root),
        "tools": tools_dir(root),
        "runtime": runtime_dir(root),
        "cases": cases_dir(root),
        "agent_buffer": agent_buffer_dir(root),
        "logs": logs_dir(root),
    }
    for directory in directories.values():
        directory.mkdir(parents=True, exist_ok=True)
    return directories


def safe_join(base: str | Path, *parts: str | Path) -> Path:
    """Join paths while preventing traversal outside ``base``."""
    base_path = Path(base).expanduser().resolve()
    candidate = base_path.joinpath(*parts).resolve()
    try:
        candidate.relative_to(base_path)
    except ValueError as exc:
        raise UnsafePathError(
            f"Đường dẫn {candidate} nằm ngoài thư mục cho phép {base_path}."
        ) from exc
    return candidate
