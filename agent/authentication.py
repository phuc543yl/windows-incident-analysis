"""Token and client-IP authentication for Agent HTTP endpoints."""

from __future__ import annotations

import hmac
from functools import wraps
from typing import Any, Callable, TypeVar

try:
    from flask import current_app, jsonify, request
except ModuleNotFoundError:
    current_app = None
    jsonify = None
    request = None

from agent.configuration import AgentSettings

ViewFunction = TypeVar("ViewFunction", bound=Callable[..., Any])


class AgentAuthenticator:
    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings

    def client_allowed(self, remote_addr: str | None) -> bool:
        return (
            remote_addr is not None
            and remote_addr in self.settings.allowed_client_ips
        )

    def token_valid(self, supplied: str | None) -> bool:
        if not self.settings.authentication_enabled:
            return True
        expected = self.settings.token
        if expected is None or supplied is None:
            return False
        return hmac.compare_digest(
            supplied.encode("utf-8"),
            expected.encode("utf-8"),
        )

    def authorize(
        self,
        *,
        remote_addr: str | None,
        supplied_token: str | None,
    ) -> tuple[bool, int, str]:
        if not self.client_allowed(remote_addr):
            return False, 403, "Client IP không được phép."
        if not self.token_valid(supplied_token):
            return False, 401, "Xác thực Agent thất bại."
        return True, 200, ""


def require_agent_auth(view: ViewFunction) -> ViewFunction:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        if current_app is None or jsonify is None or request is None:
            raise RuntimeError(
                "Thiếu Flask. Hãy chạy 'pip install -r requirements.txt'."
            )
        authenticator: AgentAuthenticator = current_app.extensions[
            "agent_authenticator"
        ]
        settings = authenticator.settings
        allowed, status_code, message = authenticator.authorize(
            remote_addr=request.remote_addr,
            supplied_token=request.headers.get(settings.token_header),
        )
        if not allowed:
            logger = current_app.extensions["agent_logger"]
            logger.log(
                "authentication_failed",
                status="failed",
                details={
                    "remote_addr": request.remote_addr or "",
                    "status_code": status_code,
                },
            )
            return jsonify({"error": message}), status_code
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]
