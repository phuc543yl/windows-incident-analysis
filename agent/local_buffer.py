"""Persistent on-disk task state and Evidence Bundle buffer."""

from __future__ import annotations

import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from common.exceptions import AgentError, JsonFileError
from common.json_utils import read_json_object, write_json
from common.time_utils import parse_timestamp, utc_now
from models import to_json_value

TASK_STATUSES = {
    "queued",
    "running",
    "completed",
    "failed",
}


@dataclass(slots=True)
class AgentTask:
    task_id: str
    collection_plan: dict[str, Any]
    status: str = "queued"
    created_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    collection_results: tuple[dict[str, Any], ...] = ()
    bundle_path: str | None = None
    bundle_sha256: str | None = None
    bundle_size_bytes: int | None = None
    bundle_available: bool = False
    transferred_at: datetime | None = None
    error: str = ""

    def __post_init__(self) -> None:
        if not self.task_id.startswith("TASK-"):
            raise ValueError("task_id không hợp lệ.")
        self.status = str(self.status).strip().casefold()
        if self.status not in TASK_STATUSES:
            raise ValueError(f"Task status không hợp lệ: {self.status}")
        self.collection_plan = dict(self.collection_plan)
        self.created_at = parse_timestamp(self.created_at)
        self.started_at = (
            parse_timestamp(self.started_at)
            if self.started_at is not None
            else None
        )
        self.finished_at = (
            parse_timestamp(self.finished_at)
            if self.finished_at is not None
            else None
        )
        self.transferred_at = (
            parse_timestamp(self.transferred_at)
            if self.transferred_at is not None
            else None
        )
        self.collection_results = tuple(
            dict(item) for item in self.collection_results
        )

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentTask":
        return cls(
            task_id=data["task_id"],
            collection_plan=dict(data["collection_plan"]),
            status=data.get("status", "queued"),
            created_at=data.get("created_at") or utc_now(),
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            collection_results=tuple(
                data.get("collection_results", ())
            ),
            bundle_path=data.get("bundle_path"),
            bundle_sha256=data.get("bundle_sha256"),
            bundle_size_bytes=data.get("bundle_size_bytes"),
            bundle_available=bool(
                data.get("bundle_available", False)
            ),
            transferred_at=data.get("transferred_at"),
            error=data.get("error", ""),
        )


class LocalBuffer:
    def __init__(
        self,
        root: str | Path,
        *,
        delete_after_successful_transfer: bool = True,
        retention_hours_on_failure: float = 24,
    ) -> None:
        candidate = Path(root).expanduser()
        if candidate.is_symlink():
            raise AgentError(
                "Agent buffer không được là symbolic link."
            )
        self.root = candidate.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.delete_after_successful_transfer = bool(
            delete_after_successful_transfer
        )
        self.retention_hours_on_failure = float(
            retention_hours_on_failure
        )
        if self.retention_hours_on_failure <= 0:
            raise ValueError(
                "retention_hours_on_failure phải là số dương."
            )
        self._lock = threading.RLock()

    def create(self, collection_plan: dict[str, Any]) -> AgentTask:
        with self._lock:
            task = AgentTask(
                task_id=f"TASK-{uuid4().hex}",
                collection_plan=collection_plan,
            )
            directory = self.task_directory(task.task_id)
            directory.mkdir(parents=False, exist_ok=False)
            self.workspace(task.task_id).mkdir()
            self._save(task)
            return task

    def get(self, task_id: str) -> AgentTask:
        path = self.task_file(task_id)
        try:
            return AgentTask.from_dict(read_json_object(path))
        except JsonFileError as exc:
            if not path.exists():
                raise AgentError(
                    f"Không tìm thấy Agent task: {task_id}"
                ) from exc
            raise AgentError(str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(
                f"Agent task {task_id} không hợp lệ: {exc}"
            ) from exc

    def list(self) -> tuple[AgentTask, ...]:
        tasks: list[AgentTask] = []
        for path in sorted(self.root.glob("TASK-*/task.json")):
            try:
                tasks.append(self.get(path.parent.name))
            except AgentError:
                continue
        return tuple(
            sorted(
                tasks,
                key=lambda item: item.created_at,
                reverse=True,
            )
        )

    def mark_running(self, task_id: str) -> AgentTask:
        return self._transition(
            task_id,
            expected={"queued"},
            status="running",
            started_at=utc_now(),
        )

    def mark_completed(
        self,
        task_id: str,
        *,
        collection_results: tuple[dict[str, Any], ...],
        bundle_path: Path,
        bundle_sha256: str,
        bundle_size_bytes: int,
    ) -> AgentTask:
        resolved = bundle_path.expanduser().resolve()
        task_dir = self.task_directory(task_id)
        try:
            relative = resolved.relative_to(task_dir)
        except ValueError as exc:
            raise AgentError("Bundle nằm ngoài task buffer.") from exc
        if resolved.is_symlink() or not resolved.is_file():
            raise AgentError("Bundle trong task buffer không hợp lệ.")
        return self._transition(
            task_id,
            expected={"running"},
            status="completed",
            finished_at=utc_now(),
            collection_results=collection_results,
            bundle_path=relative.as_posix(),
            bundle_sha256=bundle_sha256,
            bundle_size_bytes=bundle_size_bytes,
            bundle_available=True,
            error="",
        )

    def mark_failed(self, task_id: str, error: str) -> AgentTask:
        return self._transition(
            task_id,
            expected={"queued", "running"},
            status="failed",
            finished_at=utc_now(),
            error=_safe_error(error),
            bundle_available=False,
        )

    def bundle_for(self, task_id: str) -> tuple[AgentTask, Path]:
        task = self.get(task_id)
        if (
            task.status != "completed"
            or not task.bundle_available
            or not task.bundle_path
        ):
            raise AgentError(
                f"Bundle chưa sẵn sàng cho task {task_id}."
            )
        candidate = self.task_directory(task_id).joinpath(
            *task.bundle_path.replace("\\", "/").split("/")
        )
        if candidate.is_symlink():
            raise AgentError("Bundle không được là symbolic link.")
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.task_directory(task_id))
        except ValueError as exc:
            raise AgentError("Bundle path không an toàn.") from exc
        if not resolved.is_file():
            raise AgentError("Không tìm thấy bundle trong buffer.")
        return task, resolved

    def mark_transferred(self, task_id: str) -> AgentTask:
        with self._lock:
            task = self.get(task_id)
            if task.status != "completed":
                raise AgentError("Chỉ task completed mới được transfer.")
            task.transferred_at = utc_now()
            if self.delete_after_successful_transfer and task.bundle_path:
                bundle = self.task_directory(task_id).joinpath(
                    *task.bundle_path.split("/")
                )
                bundle.unlink(missing_ok=True)
                task.bundle_available = False
            self._save(task)
            return task

    def cleanup_failed(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        cutoff = (now or utc_now()) - timedelta(
            hours=self.retention_hours_on_failure
        )
        removed: list[str] = []
        with self._lock:
            for task in self.list():
                reference = task.finished_at or task.created_at
                if task.status != "failed" or reference > cutoff:
                    continue
                directory = self.task_directory(task.task_id)
                shutil.rmtree(directory)
                removed.append(task.task_id)
        return tuple(removed)

    def task_directory(self, task_id: str) -> Path:
        normalized = _task_id(task_id)
        candidate = self.root / normalized
        if candidate.is_symlink():
            raise AgentError(
                "Task directory không được là symbolic link."
            )
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise AgentError("Task directory nằm ngoài buffer.") from exc
        return candidate

    def task_file(self, task_id: str) -> Path:
        return self.task_directory(task_id) / "task.json"

    def workspace(self, task_id: str) -> Path:
        candidate = self.task_directory(task_id) / "workspace"
        if candidate.is_symlink():
            raise AgentError(
                "Task workspace không được là symbolic link."
            )
        return candidate

    def _transition(
        self,
        task_id: str,
        *,
        expected: set[str],
        status: str,
        **changes: Any,
    ) -> AgentTask:
        with self._lock:
            task = self.get(task_id)
            if task.status not in expected:
                raise AgentError(
                    f"Task không thể chuyển từ {task.status} sang {status}."
                )
            task.status = status
            for key, value in changes.items():
                setattr(task, key, value)
            self._save(task)
            return task

    def _save(self, task: AgentTask) -> Path:
        return write_json(self.task_file(task.task_id), task.to_dict())


def _task_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("TASK-")
        or len(value) != 37
        or any(
            character not in "0123456789abcdef"
            for character in value[5:]
        )
    ):
        raise AgentError("task_id không hợp lệ.")
    return value


def _safe_error(value: str, limit: int = 1000) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."
