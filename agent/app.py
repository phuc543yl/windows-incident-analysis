"""Application factory for the authenticated Windows collection Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify
from werkzeug.exceptions import RequestEntityTooLarge

from clients.local_client import LocalClient
from collection.collector_registry import CollectorRegistry
from common.exceptions import AgentError
from agent.agent_logger import AgentLogger
from agent.authentication import AgentAuthenticator
from agent.configuration import AgentSettings
from agent.local_buffer import LocalBuffer
from agent.routes import api
from agent.task_executor import TaskExecutor


def create_app(
    config_path: str | Path = "config/agent.json",
    *,
    root: str | Path | None = None,
    environment: dict[str, str] | None = None,
    registry: CollectorRegistry | None = None,
    local_client: LocalClient | None = None,
    testing: bool = False,
) -> Flask:
    settings = AgentSettings.load(
        config_path,
        root=root,
        environment=environment,
    )
    app = Flask(__name__)
    app.config.update(
        TESTING=bool(testing),
        JSON_SORT_KEYS=True,
        MAX_CONTENT_LENGTH=min(
            settings.max_file_size_bytes,
            1024 * 1024,
        ),
    )
    logger = AgentLogger(
        settings.audit_file,
        enabled=settings.audit_enabled,
        redact_authentication_values=(
            settings.redact_authentication_values
        ),
    )
    buffer = LocalBuffer(
        settings.buffer_directory,
        delete_after_successful_transfer=(
            settings.delete_after_successful_transfer
        ),
        retention_hours_on_failure=(
            settings.retention_hours_on_failure
        ),
    )
    authenticator = AgentAuthenticator(settings)
    executor = TaskExecutor(
        settings,
        buffer,
        logger,
        registry=registry,
        local_client=local_client,
    )
    app.extensions.update(
        {
            "agent_settings": settings,
            "agent_logger": logger,
            "agent_buffer": buffer,
            "agent_authenticator": authenticator,
            "agent_executor": executor,
        }
    )
    app.register_blueprint(api)

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge):
        return jsonify({"error": "Request body vượt giới hạn."}), 413

    @app.errorhandler(404)
    def not_found(_error: Any):
        return jsonify({"error": "Không tìm thấy endpoint."}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error: Any):
        return jsonify({"error": "HTTP method không được hỗ trợ."}), 405

    logger.log(
        "agent_initialized",
        details={
            "agent_id": settings.agent_id,
            "host": settings.host,
            "port": settings.port,
            "collector_allowlist": list(
                settings.collector_allowlist
            ),
        },
    )
    buffer.cleanup_failed()
    return app


def shutdown_app(app: Flask, *, wait: bool = True) -> None:
    executor = app.extensions.get("agent_executor")
    if executor is not None:
        executor.close(wait=wait)


__all__ = ["create_app", "shutdown_app"]
