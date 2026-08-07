"""Metadata for one collected or derived evidence item."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from common.enums import ArtifactType, EvidenceCategory
from common.time_utils import parse_timestamp, utc_now
from models import (
    enum_from_value,
    new_id,
    optional_timestamp,
    portable_path,
    require_non_empty,
    to_json_value,
)


@dataclass(slots=True)
class EvidenceItem:
    case_id: str
    artifact_type: ArtifactType
    source_path: str
    stored_path: str
    collector_id: str
    hostname: str
    category: EvidenceCategory = EvidenceCategory.RAW_ARTIFACT
    evidence_id: str = field(default_factory=lambda: new_id("EVID"))
    sha256: str | None = None
    size_bytes: int = 0
    collected_at: datetime = field(default_factory=utc_now)
    source_created_at: datetime | None = None
    source_modified_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    SHA256_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.evidence_id = require_non_empty(self.evidence_id, "evidence_id")
        self.artifact_type = enum_from_value(
            ArtifactType,
            self.artifact_type,
            "artifact_type",
        )
        self.category = enum_from_value(
            EvidenceCategory,
            self.category,
            "category",
        )
        self.source_path = portable_path(self.source_path, "source_path")
        self.stored_path = portable_path(self.stored_path, "stored_path")
        self.collector_id = require_non_empty(
            self.collector_id,
            "collector_id",
        )
        self.hostname = require_non_empty(self.hostname, "hostname")
        if isinstance(self.size_bytes, bool) or not isinstance(
            self.size_bytes,
            int,
        ):
            raise TypeError("size_bytes phải là số nguyên.")
        if self.size_bytes < 0:
            raise ValueError("size_bytes phải là số nguyên không âm.")
        if self.sha256 is not None:
            self.sha256 = self.sha256.lower().strip()
            if not self.SHA256_PATTERN.fullmatch(self.sha256):
                raise ValueError("sha256 phải gồm đúng 64 ký tự hexadecimal.")
        self.collected_at = parse_timestamp(self.collected_at)
        self.source_created_at = optional_timestamp(self.source_created_at)
        self.source_modified_at = optional_timestamp(self.source_modified_at)
        self.metadata = dict(self.metadata)

    @property
    def hash_verified(self) -> bool:
        return self.sha256 is not None

    def set_hash(self, digest: str, size_bytes: int) -> None:
        normalized = require_non_empty(digest, "digest").lower()
        if not self.SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("SHA-256 không hợp lệ.")
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
            raise TypeError("size_bytes phải là số nguyên.")
        if size_bytes < 0:
            raise ValueError("size_bytes phải là số nguyên không âm.")
        self.sha256 = normalized
        self.size_bytes = size_bytes

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceItem":
        return cls(
            case_id=data["case_id"],
            artifact_type=data["artifact_type"],
            source_path=data["source_path"],
            stored_path=data["stored_path"],
            collector_id=data["collector_id"],
            hostname=data["hostname"],
            category=data.get(
                "category",
                EvidenceCategory.RAW_ARTIFACT.value,
            ),
            evidence_id=data.get("evidence_id") or new_id("EVID"),
            sha256=data.get("sha256"),
            size_bytes=int(data.get("size_bytes", 0)),
            collected_at=data.get("collected_at") or utc_now(),
            source_created_at=data.get("source_created_at"),
            source_modified_at=data.get("source_modified_at"),
            metadata=dict(data.get("metadata", {})),
        )


def stable_evidence_id(
    case_id: str,
    stored_path: str,
    digest: str,
) -> str:
    """Return the same Evidence ID on Agent and analysis workstation."""

    value = f"{case_id}\0{stored_path}\0{digest}".encode("utf-8")
    return f"EVID-{hashlib.sha256(value).hexdigest()[:24]}"
