"""Load and validate investigation profiles from ``config/``."""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from common.exceptions import ConfigurationError, JsonFileError
from common.json_utils import read_json_object
from common.paths import config_dir, project_root, safe_join
from models.collection_plan import CollectionPlan


class ProfileService:
    PROFILE_ID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^[a-z][a-z0-9_]*$"
    )

    def __init__(self, root: str | Path | None = None) -> None:
        self.project = project_root(root)
        self.profiles_directory = safe_join(
            config_dir(self.project),
            "investigation_profiles",
        )

    def list_profiles(self) -> list[dict[str, Any]]:
        if not self.profiles_directory.is_dir():
            raise ConfigurationError(
                f"Không tìm thấy thư mục profile: {self.profiles_directory}"
            )
        return [
            self._load_profile_file(path)
            for path in sorted(self.profiles_directory.glob("*.json"))
        ]

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        normalized_id = self._validate_profile_id(profile_id)
        profile_path = safe_join(
            self.profiles_directory,
            f"{normalized_id}.json",
        )
        if not profile_path.is_file():
            raise ConfigurationError(
                f"Không tìm thấy investigation profile: {normalized_id}"
            )
        return self._load_profile_file(profile_path)

    def profile_exists(self, profile_id: str) -> bool:
        try:
            normalized_id = self._validate_profile_id(profile_id)
        except ConfigurationError:
            return False
        return safe_join(
            self.profiles_directory,
            f"{normalized_id}.json",
        ).is_file()

    def build_collection_plan(
        self,
        *,
        case_id: str,
        profile_id: str,
        mode: str,
        target_agent_id: str | None = None,
        time_range_start: datetime | str | None = None,
        time_range_end: datetime | str | None = None,
    ) -> CollectionPlan:
        profile = self.get_profile(profile_id)
        options = {
            "profile_name": profile["name"],
            "default_time_window_hours": profile["default_time_window_hours"],
            "required_artifacts": list(profile["required_artifacts"]),
            "optional_artifacts": list(profile["optional_artifacts"]),
            "tools": list(profile["tools"]),
            "detection_rules": list(profile["detection_rules"]),
            "correlation_profile": profile["correlation_profile"],
        }
        return CollectionPlan(
            case_id=case_id,
            profile_id=profile["profile_id"],
            mode=mode,
            live_collectors=tuple(profile["live_collectors"]),
            artifact_collectors=tuple(profile["artifact_collectors"]),
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            target_agent_id=target_agent_id,
            options=options,
        )

    def _load_profile_file(self, path: Path) -> dict[str, Any]:
        try:
            profile = read_json_object(path)
        except JsonFileError as exc:
            raise ConfigurationError(str(exc)) from exc
        self._validate_profile(profile, expected_id=path.stem)
        return deepcopy(profile)

    def _validate_profile_id(self, profile_id: str) -> str:
        if not isinstance(profile_id, str):
            raise ConfigurationError("profile_id phải là chuỗi.")
        normalized_id = profile_id.strip().lower()
        if not self.PROFILE_ID_PATTERN.fullmatch(normalized_id):
            raise ConfigurationError(f"profile_id không hợp lệ: {profile_id}")
        return normalized_id

    def _validate_profile(
        self,
        profile: dict[str, Any],
        *,
        expected_id: str,
    ) -> None:
        required_keys = {
            "schema_version",
            "profile_id",
            "name",
            "description",
            "hypothesis",
            "default_time_window_hours",
            "live_collectors",
            "artifact_collectors",
            "required_artifacts",
            "optional_artifacts",
            "tools",
            "detection_rules",
            "correlation_profile",
        }
        missing = required_keys - set(profile)
        if missing:
            raise ConfigurationError(
                f"Profile {expected_id} thiếu trường: {sorted(missing)}"
            )
        profile_id = self._validate_profile_id(profile["profile_id"])
        if profile_id != expected_id:
            raise ConfigurationError(
                f"profile_id {profile_id} không khớp tên file {expected_id}."
            )
        if profile["schema_version"] != 1:
            raise ConfigurationError(
                f"Profile {profile_id} có schema_version không được hỗ trợ."
            )
        if (
            not isinstance(profile["default_time_window_hours"], int)
            or profile["default_time_window_hours"] <= 0
        ):
            raise ConfigurationError(
                "default_time_window_hours phải là số nguyên dương."
            )
        for key in (
            "live_collectors",
            "artifact_collectors",
            "required_artifacts",
            "optional_artifacts",
            "tools",
            "detection_rules",
        ):
            if not isinstance(profile[key], list):
                raise ConfigurationError(f"{key} trong profile phải là list.")
