"""HTTP client used by the analyst workstation to communicate with Agent."""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

try:
    import requests
except ModuleNotFoundError:  # Local Mode remains usable before dependencies.
    requests = None

from common.enums import OperationMode
from common.exceptions import (
    ClientConnectionError,
    ClientError,
    ConfigurationError,
    IntegrityVerificationError,
)
from common.json_utils import read_json_object
from clients.base_client import BaseClient
from models.collection_plan import CollectionPlan

_TERMINAL_SUCCESS_STATES = {"completed", "succeeded", "success"}
_TERMINAL_FAILURE_STATES = {"cancelled", "failed", "error"}
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class AgentClient(BaseClient):
    """Submit allowlisted collection plans and retrieve evidence bundles."""

    mode = OperationMode.AGENT

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        token_header: str = "X-Agent-Token",
        timeout_seconds: int | float = 180,
        session: Any | None = None,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds)
        self.base_url = _validate_base_url(base_url)
        self.token_header = _validate_header_name(token_header)
        self.token = token.strip() if token and token.strip() else None
        if session is None:
            if requests is None:
                raise ClientConnectionError(
                    "Thiếu thư viện requests. Hãy chạy "
                    "'pip install -r requirements.txt'."
                )
            session = requests.Session()
        self.session = session

    @classmethod
    def from_config(
        cls,
        config_path: str | Path = "config/agent.json",
        *,
        session: Any | None = None,
    ) -> "AgentClient":
        config = read_json_object(config_path)
        try:
            agent = config["agent"]
            authentication = config["authentication"]
            transport = config["transport"]
            host = str(agent["host"]).strip()
            port = int(agent["port"])
            timeout = agent["request_timeout_seconds"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"Cấu hình Agent Client không hợp lệ: {exc}"
            ) from exc

        if not host or not 1 <= port <= 65535:
            raise ConfigurationError("Host hoặc port của Agent không hợp lệ.")
        scheme = "https" if transport.get("https_enabled") else "http"
        authentication_enabled = bool(authentication.get("enabled", True))
        token = None
        if authentication_enabled:
            token_env = str(authentication.get("token_env", "")).strip()
            if not token_env:
                raise ConfigurationError(
                    "Thiếu authentication.token_env trong agent.json."
                )
            token = os.getenv(token_env)
            if not token:
                raise ConfigurationError(
                    f"Thiếu biến môi trường xác thực Agent: {token_env}"
                )

        return cls(
            f"{scheme}://{host}:{port}",
            token=token,
            token_header=str(
                authentication.get("token_header", "X-Agent-Token")
            ),
            timeout_seconds=timeout,
            session=session,
        )

    def health_check(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/health")

    def submit_collection(
        self,
        plan: CollectionPlan | Mapping[str, Any],
    ) -> str:
        payload = _plan_payload(plan)
        mode = payload.get("mode")
        mode_value = mode.value if isinstance(mode, OperationMode) else mode
        if mode_value != OperationMode.AGENT.value:
            raise ValueError(
                "AgentClient chỉ nhận Collection Plan ở Agent Mode."
            )
        response = self._request_json(
            "POST",
            "/api/v1/tasks",
            payload={"collection_plan": payload},
        )
        task_id = response.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            raise ClientError("Agent không trả về task_id hợp lệ.")
        return task_id.strip()

    def get_task(self, task_id: str) -> dict[str, Any]:
        normalized_id = _require_identifier(task_id, "task_id")
        return self._request_json(
            "GET",
            f"/api/v1/tasks/{quote(normalized_id, safe='')}",
        )

    def wait_for_task(
        self,
        task_id: str,
        *,
        poll_interval_seconds: int | float = 1,
        max_wait_seconds: int | float | None = None,
    ) -> dict[str, Any]:
        poll_interval = self.validate_timeout(poll_interval_seconds)
        max_wait = (
            self.timeout_seconds
            if max_wait_seconds is None
            else self.validate_timeout(max_wait_seconds)
        )
        deadline = time.monotonic() + max_wait

        while True:
            task = self.get_task(task_id)
            state = str(task.get("status", "")).strip().lower()
            if state in _TERMINAL_SUCCESS_STATES:
                return task
            if state in _TERMINAL_FAILURE_STATES:
                message = _safe_response_text(str(task.get("error", state)))
                raise ClientError(
                    f"Agent task {task_id} thất bại: {message}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientConnectionError(
                    f"Hết thời gian chờ Agent task {task_id}."
                )
            time.sleep(min(poll_interval, remaining))

    def download_bundle(
        self,
        task_id: str,
        destination: str | Path,
        *,
        expected_sha256: str | None = None,
        overwrite: bool = False,
    ) -> Path:
        normalized_id = _require_identifier(task_id, "task_id")
        destination_path = Path(destination).expanduser().resolve()
        if destination_path.exists() and not overwrite:
            raise FileExistsError(
                f"Evidence Bundle đã tồn tại: {destination_path}"
            )
        expected_hash = _normalize_sha256(expected_sha256)
        endpoint = (
            f"/api/v1/tasks/{quote(normalized_id, safe='')}/bundle"
        )

        try:
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                headers=self._headers(),
                timeout=self.timeout_seconds,
                stream=True,
            )
        except _request_exception_types() as exc:
            raise ClientConnectionError(
                f"Không thể tải Evidence Bundle từ Agent: {exc}"
            ) from exc
        self._raise_for_status(response)

        header_hash = _normalize_sha256(
            response.headers.get("X-Content-SHA256")
            or response.headers.get("X-SHA256")
        )
        required_hash = expected_hash or header_hash
        temporary_path = destination_path.with_name(
            f".{destination_path.name}.part"
        )
        digest = hashlib.sha256()

        try:
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            with temporary_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    digest.update(chunk)
            actual_hash = digest.hexdigest()
            if required_hash and actual_hash != required_hash:
                raise IntegrityVerificationError(
                    "SHA-256 của Evidence Bundle không khớp."
                )
            temporary_path.replace(destination_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        return destination_path

    def close(self) -> None:
        self.session.close()

    def _request_json(
        self,
        method: str,
        endpoint: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{endpoint}",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout_seconds,
            )
        except _request_exception_types() as exc:
            raise ClientConnectionError(
                f"Không thể kết nối Agent tại {self.base_url}: {exc}"
            ) from exc
        self._raise_for_status(response)
        try:
            value = response.json()
        except ValueError as exc:
            raise ClientError("Agent trả về JSON không hợp lệ.") from exc
        if not isinstance(value, dict):
            raise ClientError("Agent response phải là JSON object.")
        return value

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers[self.token_header] = self.token
        return headers

    def _raise_for_status(self, response: Any) -> None:
        if 200 <= response.status_code < 300:
            return
        message = _safe_response_text(response.text, secret=self.token)
        error_type = (
            ClientConnectionError
            if response.status_code >= 500
            else ClientError
        )
        raise error_type(
            f"Agent HTTP {response.status_code}: {message}"
        )


def _plan_payload(
    plan: CollectionPlan | Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(plan, CollectionPlan):
        return plan.to_dict()
    if isinstance(plan, Mapping):
        return dict(plan)
    raise TypeError("plan phải là CollectionPlan hoặc mapping.")


def _validate_base_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("base_url không được để trống.")
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("base_url của Agent không hợp lệ.")
    return normalized


def _validate_header_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\r" in value
        or "\n" in value
    ):
        raise ValueError("token_header không hợp lệ.")
    return value.strip()


def _require_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} không được để trống.")
    return value.strip()


def _normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not _SHA256_PATTERN.fullmatch(normalized):
        raise ValueError("SHA-256 phải gồm đúng 64 ký tự hexadecimal.")
    return normalized


def _safe_response_text(
    value: str,
    *,
    secret: str | None = None,
    limit: int = 1000,
) -> str:
    compact = " ".join(value.split())
    if secret:
        compact = compact.replace(secret, "***")
    if not compact:
        return "không có nội dung phản hồi"
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit]}..."


def _request_exception_types() -> tuple[type[BaseException], ...]:
    if requests is None:
        return (OSError,)
    return (requests.RequestException, OSError)
