"""Stable string enums shared by models, services, and serializers."""

from __future__ import annotations

from enum import Enum


class StringEnum(str, Enum):
    """Enum whose members serialize naturally as lowercase strings."""

    def __str__(self) -> str:
        return self.value


class OperationMode(StringEnum):
    LOCAL = "local"
    AGENT = "agent"


class CaseStatus(StringEnum):
    OPEN = "open"
    CLOSED = "closed"


class CollectionStatus(StringEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class EvidenceCategory(StringEnum):
    LIVE = "live"
    RAW_ARTIFACT = "raw_artifact"
    TOOL_OUTPUT = "tool_output"
    NORMALIZED = "normalized"
    REPORT = "report"


class ArtifactType(StringEnum):
    SYSTEM = "system"
    USERS = "users"
    PROCESSES = "processes"
    NETWORK = "network"
    SERVICES = "services"
    STARTUP = "startup"
    EVENT_LOGS = "event_logs"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    REGISTRY = "registry"
    MFT = "mft"
    SCHEDULED_TASKS = "scheduled_tasks"
    FIREWALL_LOGS = "firewall_logs"
    FILES = "files"
    MEMORY = "memory"


class FindingSeverity(StringEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StringEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not_confirmed"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class CIAImpact(StringEnum):
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"


class ToolRunStatus(StringEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ReportFormat(StringEnum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
