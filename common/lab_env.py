"""Load local lab environment variables without putting secrets in JSON."""

from __future__ import annotations

import os
from pathlib import Path

from common.paths import project_root

LAB_ENV_FILENAME = ".env.lab"
DEFAULT_AGENT_TOKEN_ENV = "WINDOWS_FORENSIC_AGENT_TOKEN"
DEFAULT_AGENT_TOKEN = "croweye-lab-2026"
PROJECT_ROOT_ENV = "WINDOWS_FORENSIC_ROOT"

LAB_DEFAULTS = {
    DEFAULT_AGENT_TOKEN_ENV: DEFAULT_AGENT_TOKEN,
}


def load_lab_env(
    root: str | Path | None = None,
    *,
    overwrite: bool = False,
) -> dict[str, str]:
    """Load ``.env.lab`` then apply lab defaults for any still-missing keys.

    Existing process environment wins unless ``overwrite`` is true. Missing
    files are ignored so tests and production hosts stay unchanged unless an
    entry point explicitly calls this helper.
    """
    resolved_root = project_root(root)
    applied: dict[str, str] = {}
    env_path = resolved_root / LAB_ENV_FILENAME
    file_values = _parse_env_file(env_path) if env_path.is_file() else {}
    merged = {**LAB_DEFAULTS, **file_values}

    if PROJECT_ROOT_ENV not in merged:
        merged[PROJECT_ROOT_ENV] = str(resolved_root)

    for key, value in merged.items():
        if not key or value is None or str(value).strip() == "":
            continue
        text = str(value)
        if not overwrite and os.environ.get(key):
            continue
        os.environ[key] = text
        applied[key] = text
    return applied


def describe_agent_token(
    token_env: str = DEFAULT_AGENT_TOKEN_ENV,
) -> str:
    """Return a short UI-safe status for the Agent token environment."""
    if os.getenv(token_env):
        return f"Đã nạp {token_env}"
    return f"Chưa có {token_env}"


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        text = value.strip().strip('"').strip("'")
        if key:
            values[key] = text
    return values
