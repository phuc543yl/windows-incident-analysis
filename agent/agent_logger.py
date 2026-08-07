"""Structured Agent audit logging with recursive secret redaction."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from common.json_utils import append_jsonl
from common.time_utils import utc_now_iso

_SECRET_KEYS = {
    "authorization",
    "password",
    "token",
    "api_key",
    "apikey",
    "secret",
}


class AgentLogger:
    def __init__(
        self,
        path: str | Path,
        *,
        enabled: bool = True,
        redact_authentication_values: bool = True,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.enabled = bool(enabled)
        self.redact_authentication_values = bool(
            redact_authentication_values
        )
        self._lock = threading.RLock()

    def log(
        self,
        action: str,
        *,
        status: str = "success",
        details: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return
        payload: dict[str, Any] = {
            "timestamp": utc_now_iso(),
            "action": str(action).strip(),
            "status": str(status).strip(),
            "details": dict(details or {}),
        }
        if self.redact_authentication_values:
            payload = _redact(payload)
        with self._lock:
            append_jsonl(self.path, payload)


def _redact(value: Any, key: str = "") -> Any:
    if key.casefold() in _SECRET_KEYS:
        return "***"
    if isinstance(value, dict):
        return {
            str(item_key): _redact(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value
