"""Canonical manifest schema shared by Agent and analysis workstation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from common.time_utils import parse_timestamp, utc_now
from models import require_non_empty
from models.evidence_item import EvidenceItem


@dataclass(slots=True)
class EvidenceManifest:
    """Validated schema for ``acquisition/manifest.json``."""

    case_id: str
    generated_by: str
    evidence_items: tuple[EvidenceItem, ...]
    generated_at: datetime = field(default_factory=utc_now)

    SCHEMA_VERSION: ClassVar[int] = 1
    HASH_ALGORITHM: ClassVar[str] = "sha256"

    def __post_init__(self) -> None:
        self.case_id = require_non_empty(self.case_id, "case_id")
        self.generated_by = require_non_empty(
            self.generated_by,
            "generated_by",
        )
        self.generated_at = parse_timestamp(self.generated_at)
        self.evidence_items = tuple(self.evidence_items)
        for item in self.evidence_items:
            if not isinstance(item, EvidenceItem):
                raise TypeError(
                    "evidence_items chỉ được chứa EvidenceItem."
                )
            if item.case_id != self.case_id:
                raise ValueError("EvidenceItem không khớp Case của manifest.")
            if item.sha256 is None:
                raise ValueError(
                    f"EvidenceItem {item.evidence_id} chưa có SHA-256."
                )

    @property
    def item_count(self) -> int:
        return len(self.evidence_items)

    @property
    def total_size_bytes(self) -> int:
        return sum(item.size_bytes for item in self.evidence_items)

    def to_dict(self) -> dict[str, Any]:
        from common.time_utils import to_iso8601

        return {
            "schema_version": self.SCHEMA_VERSION,
            "case_id": self.case_id,
            "generated_at": to_iso8601(self.generated_at),
            "generated_by": self.generated_by,
            "hash_algorithm": self.HASH_ALGORITHM,
            "item_count": self.item_count,
            "total_size_bytes": self.total_size_bytes,
            "evidence_items": [
                item.to_dict() for item in self.evidence_items
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceManifest":
        if not isinstance(data, dict):
            raise TypeError("Manifest phải là object.")
        if data.get("schema_version") != cls.SCHEMA_VERSION:
            raise ValueError("schema_version của manifest không được hỗ trợ.")
        if data.get("hash_algorithm") != cls.HASH_ALGORITHM:
            raise ValueError("Manifest phải sử dụng SHA-256.")
        raw_items = data.get("evidence_items")
        if not isinstance(raw_items, list):
            raise TypeError("manifest thiếu evidence_items hợp lệ.")
        if not all(isinstance(item, dict) for item in raw_items):
            raise TypeError("evidence_items phải chứa các object.")
        items = tuple(EvidenceItem.from_dict(item) for item in raw_items)
        manifest = cls(
            case_id=data["case_id"],
            generated_by=data["generated_by"],
            generated_at=data["generated_at"],
            evidence_items=items,
        )
        if data.get("item_count") != manifest.item_count:
            raise ValueError("item_count trong manifest không chính xác.")
        if data.get("total_size_bytes") != manifest.total_size_bytes:
            raise ValueError(
                "total_size_bytes trong manifest không chính xác."
            )
        return manifest
