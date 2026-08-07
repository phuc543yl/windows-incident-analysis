"""Authenticated, allowlisted Windows collection Agent."""

from agent.authentication import AgentAuthenticator
from agent.configuration import AgentSettings
from agent.local_buffer import AgentTask, LocalBuffer
from agent.task_executor import TaskExecutor


def create_app(*args, **kwargs):
    from agent.app import create_app as application_factory

    return application_factory(*args, **kwargs)


def shutdown_app(*args, **kwargs):
    from agent.app import shutdown_app as shutdown

    return shutdown(*args, **kwargs)

__all__ = [
    "AgentAuthenticator",
    "AgentSettings",
    "AgentTask",
    "LocalBuffer",
    "TaskExecutor",
    "create_app",
    "shutdown_app",
]
