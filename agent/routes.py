"""Flask routes implementing the AgentClient API contract."""

from __future__ import annotations

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    request,
    send_file,
)

from common.exceptions import AgentError
from agent.authentication import require_agent_auth

api = Blueprint("agent_api", __name__, url_prefix="/api/v1")


@api.get("/health")
@require_agent_auth
def health():
    settings = current_app.extensions["agent_settings"]
    buffer = current_app.extensions["agent_buffer"]
    tasks = buffer.list()
    return jsonify(
        {
            "status": "ok",
            "available": True,
            "agent_id": settings.agent_id,
            "task_counts": {
                state: sum(task.status == state for task in tasks)
                for state in (
                    "queued",
                    "running",
                    "completed",
                    "failed",
                )
            },
        }
    )


@api.post("/tasks")
@require_agent_auth
def create_task():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body phải là JSON object."}), 400
    plan = payload.get("collection_plan")
    if not isinstance(plan, dict):
        return jsonify(
            {"error": "collection_plan phải là JSON object."}
        ), 400
    executor = current_app.extensions["agent_executor"]
    logger = current_app.extensions["agent_logger"]
    try:
        task = executor.submit(plan, background=True)
    except (AgentError, TypeError, ValueError) as exc:
        logger.log(
            "task_rejected",
            status="failed",
            details={"error": str(exc)},
        )
        return jsonify({"error": str(exc)}), 400
    return jsonify(task.to_dict()), 202


@api.get("/tasks/<task_id>")
@require_agent_auth
def get_task(task_id: str):
    buffer = current_app.extensions["agent_buffer"]
    try:
        task = buffer.get(task_id)
    except AgentError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify(task.to_dict())


@api.get("/tasks/<task_id>/bundle")
@require_agent_auth
def download_bundle(task_id: str):
    buffer = current_app.extensions["agent_buffer"]
    logger = current_app.extensions["agent_logger"]
    try:
        task, path = buffer.bundle_for(task_id)
    except AgentError as exc:
        return jsonify({"error": str(exc)}), 409
    response: Response = send_file(
        path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{task.task_id}.zip",
        conditional=True,
    )
    response.headers["X-Content-SHA256"] = task.bundle_sha256 or ""
    response.headers["X-Agent-Task-ID"] = task.task_id

    def completed_transfer() -> None:
        try:
            buffer.mark_transferred(task.task_id)
            logger.log(
                "bundle_transferred",
                details={
                    "task_id": task.task_id,
                    "bundle_sha256": task.bundle_sha256,
                },
            )
        except AgentError as exc:
            logger.log(
                "bundle_transfer_cleanup_failed",
                status="failed",
                details={
                    "task_id": task.task_id,
                    "error": str(exc),
                },
            )

    response.call_on_close(completed_transfer)
    return response
