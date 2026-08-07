"""Shared primitives used across the Windows incident analysis toolkit."""

from common.constants import APP_NAME, APP_VERSION
from common.enums import (
    ArtifactType,
    CaseStatus,
    CIAImpact,
    CollectionStatus,
    EvidenceCategory,
    FindingSeverity,
    IncidentStatus,
    OperationMode,
    ReportFormat,
    ToolRunStatus,
)
from common.exceptions import ToolkitError

__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "ArtifactType",
    "CaseStatus",
    "CIAImpact",
    "CollectionStatus",
    "EvidenceCategory",
    "FindingSeverity",
    "IncidentStatus",
    "OperationMode",
    "ReportFormat",
    "ToolRunStatus",
    "ToolkitError",
]
