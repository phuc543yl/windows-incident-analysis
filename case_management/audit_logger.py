"""Append-only audit records for Case lifecycle actions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from common.exceptions import JsonFileError
from common.json_utils import append_jsonl
from common.time_utils import utc_now_iso
from case_management.case_paths import CasePaths, get_case_paths

SENSITIVE_KEY_PARTS = (
    "password",
    "token",
    "authorization",
    "api_key",
    "secret",
)


class AuditLogger:
    def __init__(
        self,
        case_id: str,
        root: str | Path | None = None,
    ) -> None:
        self.paths: CasePaths = get_case_paths(case_id, root)

    def log(
        self,
        action: str,
        *,
        actor: str = "",
        status: str = "success",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(action, str) or not action.strip():
            raise ValueError("Audit action không được để trống.")
        if not isinstance(status, str) or not status.strip():
            raise ValueError("Audit status không được để trống.")

        entry = {
            "timestamp": utc_now_iso(),
            "case_id": self.paths.case_id,
            "action": action.strip(),
            "actor": actor.strip() if isinstance(actor, str) else str(actor),
            "status": status.strip().lower(),
            "details": _redact(details or {}),
        }
        append_jsonl(self.paths.audit_log, entry)
        return entry

    def read_entries(self) -> list[dict[str, Any]]:
        if not self.paths.audit_log.exists():
            return []

        entries: list[dict[str, Any]] = []
        try:
            with self.paths.audit_log.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise JsonFileError(
                            f"Audit log lỗi tại dòng {line_number}: {exc.msg}"
                        ) from exc
                    if not isinstance(value, dict):
                        raise JsonFileError(
                            f"Audit log dòng {line_number} phải là object."
                        )
                    entries.append(value)
        except OSError as exc:
            raise JsonFileError(
                f"Không thể đọc audit log {self.paths.audit_log}: {exc}"
            ) from exc
        return entries


def _redact(value: Any, key: str = "") -> Any:
    normalized_key = key.lower()
    if any(part in normalized_key for part in SENSITIVE_KEY_PARTS):
        return "***"
    if isinstance(value, dict):
        return {
            str(nested_key): _redact(nested_value, str(nested_key))
            for nested_key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    return value
