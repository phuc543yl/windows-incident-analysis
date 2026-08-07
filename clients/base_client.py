"""Shared contracts for collection clients."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from common.constants import DEFAULT_COLLECTION_TIMEOUT_SECONDS
from common.enums import OperationMode
from common.time_utils import to_iso8601


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Result of one local PowerShell execution."""

    executable: str
    arguments: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime

    def __post_init__(self) -> None:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at không được trước started_at.")

    @property
    def success(self) -> bool:
        return self.return_code == 0

    @property
    def duration_seconds(self) -> float:
        return max(
            0.0,
            (self.finished_at - self.started_at).total_seconds(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "arguments": list(self.arguments),
            "return_code": self.return_code,
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": to_iso8601(self.started_at),
            "finished_at": to_iso8601(self.finished_at),
            "duration_seconds": self.duration_seconds,
        }


class BaseClient(ABC):
    """Minimal lifecycle shared by local and remote clients."""

    mode: OperationMode

    def __init__(
        self,
        *,
        timeout_seconds: int | float = DEFAULT_COLLECTION_TIMEOUT_SECONDS,
    ) -> None:
        self.timeout_seconds = self.validate_timeout(timeout_seconds)

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Return transport availability and endpoint information."""

    def close(self) -> None:
        """Release transport resources when a client owns any."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @staticmethod
    def validate_timeout(value: int | float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("timeout_seconds phải là số.")
        timeout = float(value)
        if timeout <= 0:
            raise ValueError("timeout_seconds phải lớn hơn 0.")
        return timeout
