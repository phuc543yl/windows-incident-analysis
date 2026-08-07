"""Application service for creating, updating, and closing Cases."""

from __future__ import annotations

import getpass
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from common.constants import (
    CASE_ID_DATE_FORMAT,
    CASE_ID_PREFIX,
    CASE_ID_SEQUENCE_WIDTH,
)
from common.enums import CaseStatus, OperationMode
from common.json_utils import write_json
from common.paths import cases_dir
from common.time_utils import to_iso8601, utc_now
from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from case_management.profile_service import ProfileService
from models import enum_from_value, require_non_empty, string_tuple
from models.case import Case
from models.target_host import TargetHost

_UNSET = object()


class CaseService:
    _creation_lock: ClassVar[threading.Lock] = threading.Lock()
    _CASE_SEQUENCE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^CASE-(\d{8})-(\d{3,6})$"
    )

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str | None = None,
    ) -> None:
        self.repository = CaseRepository(root)
        self.profile_service = ProfileService(self.repository.project)
        self.actor = actor.strip() if actor and actor.strip() else _default_actor()

    def create_case(
        self,
        *,
        title: str,
        target_hostname: str,
        mode: OperationMode | str = OperationMode.LOCAL,
        profile_id: str = "general_investigation",
        description: str = "",
        hypothesis: str = "",
        target_ip_addresses: tuple[str, ...] = (),
        target_agent_id: str | None = None,
        created_by: str | None = None,
        tags: tuple[str, ...] = (),
        time_range_start: datetime | str | None = None,
        time_range_end: datetime | str | None = None,
    ) -> Case:
        normalized_mode = enum_from_value(OperationMode, mode, "mode")
        profile = self.profile_service.get_profile(profile_id)
        now = utc_now()

        with self._creation_lock:
            case_id = self._next_case_id(now)
            target = TargetHost(
                hostname=target_hostname,
                ip_addresses=target_ip_addresses,
                agent_id=target_agent_id,
            )
            case = Case(
                case_id=case_id,
                title=title,
                target_host_id=target.host_id,
                profile_id=profile["profile_id"],
                mode=normalized_mode,
                description=description,
                hypothesis=hypothesis or profile["hypothesis"],
                created_by=created_by or self.actor,
                created_at=now,
                updated_at=now,
                tags=tags,
            )
            plan = self.profile_service.build_collection_plan(
                case_id=case_id,
                profile_id=profile["profile_id"],
                mode=normalized_mode.value,
                target_agent_id=target_agent_id,
                time_range_start=time_range_start,
                time_range_end=time_range_end,
            )
            self.repository.create(case, target, plan)

        AuditLogger(case_id, self.repository.project).log(
            "case_created",
            actor=case.created_by,
            details={
                "title": case.title,
                "target_hostname": target.hostname,
                "mode": case.mode.value,
                "profile_id": case.profile_id,
            },
        )
        return case

    def open_case(self, case_id: str) -> Case:
        return self.repository.load_case(case_id)

    def get_case_context(self, case_id: str) -> dict[str, Any]:
        case = self.repository.load_case(case_id)
        target = self.repository.load_target(case_id)
        plan = self.repository.load_collection_plan(case_id)
        return {
            "case": case.to_dict(),
            "target": target.to_dict(),
            "collection_plan": plan.to_dict(),
            "paths": self.repository.paths(case_id).to_dict(),
        }

    def list_cases(
        self,
        status: CaseStatus | str | None = None,
    ) -> list[Case]:
        return self.repository.list_cases(status=status)

    def update_case(
        self,
        case_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        hypothesis: str | None = None,
        tags: tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Case:
        case = self.repository.require_open(case_id)
        changed_fields: list[str] = []

        if title is not None:
            case.title = require_non_empty(title, "title")
            changed_fields.append("title")
        if description is not None:
            case.description = description
            changed_fields.append("description")
        if hypothesis is not None:
            case.hypothesis = hypothesis
            changed_fields.append("hypothesis")
        if tags is not None:
            case.tags = string_tuple(tags)
            changed_fields.append("tags")
        if metadata is not None:
            case.metadata.update(metadata)
            changed_fields.append("metadata")

        if changed_fields:
            case.touch()
            self.repository.save_case(case)
            AuditLogger(case_id, self.repository.project).log(
                "case_updated",
                actor=self.actor,
                details={"changed_fields": changed_fields},
            )
        return case

    def update_target(
        self,
        case_id: str,
        *,
        os_name: str | object = _UNSET,
        os_version: str | object = _UNSET,
        architecture: str | object = _UNSET,
        domain: str | object = _UNSET,
        current_user: str | object = _UNSET,
        ip_addresses: tuple[str, ...] | object = _UNSET,
        metadata: dict[str, Any] | None = None,
    ) -> TargetHost:
        self.repository.require_open(case_id)
        target = self.repository.load_target(case_id)
        changed_fields: list[str] = []

        for field_name, value in (
            ("os_name", os_name),
            ("os_version", os_version),
            ("architecture", architecture),
            ("domain", domain),
            ("current_user", current_user),
        ):
            if value is not _UNSET:
                if not isinstance(value, str):
                    raise TypeError(f"{field_name} phải là chuỗi.")
                setattr(target, field_name, value)
                changed_fields.append(field_name)
        if ip_addresses is not _UNSET:
            if not isinstance(ip_addresses, tuple):
                raise TypeError("ip_addresses phải là tuple.")
            candidate = TargetHost.from_dict(
                {
                    **target.to_dict(),
                    "ip_addresses": list(ip_addresses),
                }
            )
            target.ip_addresses = candidate.ip_addresses
            changed_fields.append("ip_addresses")
        if metadata is not None:
            target.metadata.update(metadata)
            changed_fields.append("metadata")

        if changed_fields:
            self.repository.save_target(case_id, target)
            AuditLogger(case_id, self.repository.project).log(
                "target_updated",
                actor=self.actor,
                details={"changed_fields": changed_fields},
            )
        return target

    def close_case(self, case_id: str, conclusion: str = "") -> Case:
        case = self.repository.require_open(case_id)
        case.close()
        paths = self.repository.paths(case_id)
        write_json(
            paths.conclusion_json,
            {
                "case_id": case.case_id,
                "status": "closed",
                "conclusion": conclusion.strip(),
                "closed_at": to_iso8601(case.closed_at),
                "closed_by": self.actor,
            },
        )
        self.repository.save_case(case)
        AuditLogger(case_id, self.repository.project).log(
            "case_closed",
            actor=self.actor,
            details={"conclusion_recorded": bool(conclusion.strip())},
        )
        return case

    def _next_case_id(self, timestamp: datetime) -> str:
        date_component = timestamp.strftime(CASE_ID_DATE_FORMAT)
        highest_sequence = 0
        for path in cases_dir(self.repository.project).iterdir():
            if not path.is_dir():
                continue
            match = self._CASE_SEQUENCE_PATTERN.fullmatch(path.name.upper())
            if match and match.group(1) == date_component:
                highest_sequence = max(
                    highest_sequence,
                    int(match.group(2)),
                )
        sequence = highest_sequence + 1
        return (
            f"{CASE_ID_PREFIX}-{date_component}-"
            f"{sequence:0{CASE_ID_SEQUENCE_WIDTH}d}"
        )


def _default_actor() -> str:
    try:
        return getpass.getuser() or "unknown"
    except Exception:
        return "unknown"
