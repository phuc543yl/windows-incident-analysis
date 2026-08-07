"""Build and safely override Collection Plans."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from case_management.profile_service import ProfileService
from common.enums import OperationMode
from models import enum_from_value
from models.collection_plan import CollectionPlan


class PlanBuilder:
    def __init__(self, root: str | Path | None = None) -> None:
        self.profile_service = ProfileService(root)

    def build(
        self,
        *,
        case_id: str,
        profile_id: str,
        mode: OperationMode | str = OperationMode.LOCAL,
        target_agent_id: str | None = None,
        live_collectors: tuple[str, ...] | None = None,
        artifact_collectors: tuple[str, ...] | None = None,
        time_range_start: datetime | str | None = None,
        time_range_end: datetime | str | None = None,
    ) -> CollectionPlan:
        normalized_mode = enum_from_value(OperationMode, mode, "mode")
        plan = self.profile_service.build_collection_plan(
            case_id=case_id,
            profile_id=profile_id,
            mode=normalized_mode.value,
            target_agent_id=target_agent_id,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
        )
        profile_live = set(plan.live_collectors)
        profile_artifacts = set(plan.artifact_collectors)
        selected_live = (
            plan.live_collectors
            if live_collectors is None
            else tuple(live_collectors)
        )
        selected_artifacts = (
            plan.artifact_collectors
            if artifact_collectors is None
            else tuple(artifact_collectors)
        )
        _require_subset(
            selected_live,
            profile_live,
            "live_collectors",
        )
        _require_subset(
            selected_artifacts,
            profile_artifacts,
            "artifact_collectors",
        )
        plan.live_collectors = selected_live
        plan.artifact_collectors = selected_artifacts
        plan.__post_init__()
        return plan

    @staticmethod
    def with_overrides(
        plan: CollectionPlan,
        *,
        mode: OperationMode | str | None = None,
        target_agent_id: str | None = None,
    ) -> CollectionPlan:
        data = plan.to_dict()
        if mode is not None:
            data["mode"] = enum_from_value(
                OperationMode,
                mode,
                "mode",
            ).value
        if target_agent_id is not None:
            data["target_agent_id"] = target_agent_id
        if data["mode"] == OperationMode.LOCAL.value:
            data["target_agent_id"] = None
        return CollectionPlan.from_dict(data)


def _require_subset(
    selected: tuple[str, ...],
    allowed: set[str],
    field_name: str,
) -> None:
    unknown = set(selected) - allowed
    if unknown:
        raise ValueError(
            f"{field_name} nằm ngoài investigation profile: "
            f"{sorted(unknown)}"
        )
