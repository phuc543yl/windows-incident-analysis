"""Collector contracts and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from common.constants import (
    SUPPORTED_ARTIFACT_COLLECTORS,
    SUPPORTED_LIVE_COLLECTORS,
)
from common.enums import EvidenceCategory
from common.exceptions import CollectorNotFoundError, CollectionError
from clients.local_client import LocalClient


@dataclass(frozen=True, slots=True)
class CollectorOutput:
    """Unpersisted output returned by one collector."""

    data: Any = None
    files: tuple[Path, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "files",
            tuple(Path(path).expanduser().resolve() for path in self.files),
        )
        object.__setattr__(
            self,
            "warnings",
            tuple(
                warning.strip()
                for warning in self.warnings
                if isinstance(warning, str) and warning.strip()
            ),
        )
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def record_count(self) -> int:
        if self.files:
            return len(self.files)
        if self.data is None:
            return 0
        if isinstance(self.data, dict):
            return 1 if self.data else 0
        if isinstance(self.data, (list, tuple, set)):
            return len(self.data)
        return 1


class BaseCollector(ABC):
    """Contract implemented by all Local Mode collectors."""

    collector_id: str
    category: EvidenceCategory
    output_filename: str | None = None

    @abstractmethod
    def collect(
        self,
        client: LocalClient,
        destination: Path,
        options: Mapping[str, Any],
    ) -> CollectorOutput:
        """Collect data without performing evidence hashing."""


class CollectorRegistry:
    def __init__(
        self,
        collectors: tuple[BaseCollector, ...] = (),
    ) -> None:
        self._collectors: dict[str, BaseCollector] = {}
        for collector in collectors:
            self.register(collector)

    def register(self, collector: BaseCollector) -> None:
        if not isinstance(collector, BaseCollector):
            raise TypeError("collector phải kế thừa BaseCollector.")
        collector_id = _validate_collector(collector)
        if collector_id in self._collectors:
            raise CollectionError(
                f"Collector đã được đăng ký: {collector_id}"
            )
        self._collectors[collector_id] = collector

    def get(self, collector_id: str) -> BaseCollector:
        normalized_id = _normalize_collector_id(collector_id)
        try:
            return self._collectors[normalized_id]
        except KeyError as exc:
            raise CollectorNotFoundError(
                f"Không tìm thấy collector: {normalized_id}"
            ) from exc

    def contains(self, collector_id: str) -> bool:
        try:
            normalized_id = _normalize_collector_id(collector_id)
        except (TypeError, ValueError):
            return False
        return normalized_id in self._collectors

    def ids(
        self,
        category: EvidenceCategory | str | None = None,
    ) -> tuple[str, ...]:
        if category is None:
            return tuple(sorted(self._collectors))
        try:
            category_filter = (
                category
                if isinstance(category, EvidenceCategory)
                else EvidenceCategory(str(category))
            )
        except ValueError as exc:
            raise ValueError(
                f"Evidence category không hợp lệ: {category}"
            ) from exc
        return tuple(
            sorted(
                collector_id
                for collector_id, collector in self._collectors.items()
                if collector.category is category_filter
            )
        )


def build_default_registry() -> CollectorRegistry:
    """Create the registry lazily to avoid collector import cycles."""
    from collection.artifacts.amcache_collector import AmcacheCollector
    from collection.artifacts.evtx_collector import EvtxCollector
    from collection.artifacts.file_collector import FileCollector
    from collection.artifacts.firewall_log_collector import (
        FirewallLogCollector,
    )
    from collection.artifacts.memory_collector import MemoryCollector
    from collection.artifacts.mft_collector import MftCollector
    from collection.artifacts.prefetch_collector import PrefetchCollector
    from collection.artifacts.registry_collector import RegistryCollector
    from collection.artifacts.scheduled_task_collector import (
        ScheduledTaskCollector,
    )
    from collection.live.network_collector import NetworkCollector
    from collection.live.process_collector import ProcessCollector
    from collection.live.service_collector import ServiceCollector
    from collection.live.startup_collector import StartupCollector
    from collection.live.system_collector import SystemCollector
    from collection.live.user_collector import UserCollector

    return CollectorRegistry(
        (
            SystemCollector(),
            UserCollector(),
            ProcessCollector(),
            NetworkCollector(),
            ServiceCollector(),
            StartupCollector(),
            EvtxCollector(),
            PrefetchCollector(),
            AmcacheCollector(),
            RegistryCollector(),
            MftCollector(),
            ScheduledTaskCollector(),
            FirewallLogCollector(),
            FileCollector(),
            MemoryCollector(),
        )
    )


def _normalize_collector_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("collector_id phải là chuỗi.")
    normalized = value.strip().lower()
    if not normalized:
        raise ValueError("collector_id không được để trống.")
    return normalized


def _validate_collector(collector: BaseCollector) -> str:
    collector_id = _normalize_collector_id(collector.collector_id)
    allowed = (
        SUPPORTED_LIVE_COLLECTORS
        if collector.category is EvidenceCategory.LIVE
        else SUPPORTED_ARTIFACT_COLLECTORS
        if collector.category is EvidenceCategory.RAW_ARTIFACT
        else ()
    )
    if collector_id not in allowed:
        raise CollectionError(
            f"Collector không thuộc danh sách hỗ trợ: {collector_id}"
        )
    if (
        collector.category is EvidenceCategory.LIVE
        and not collector.output_filename
    ):
        raise CollectionError(
            f"Live collector {collector_id} thiếu output_filename."
        )
    return collector_id
