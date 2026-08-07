"""Load and validate local MITRE ATT&CK mappings for rule IDs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from common.exceptions import AnalysisError, JsonFileError
from common.json_utils import read_json_object
from common.paths import config_dir, project_root


class MitreMapper:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        config_path: str | Path | None = None,
    ) -> None:
        self.project = project_root(root)
        self.config_path = (
            Path(config_path).expanduser().resolve()
            if config_path is not None
            else config_dir(self.project) / "mitre_mapping.json"
        )
        self._mappings = self._load()

    def mappings_for(self, rule_id: str) -> tuple[dict[str, Any], ...]:
        return tuple(
            dict(item)
            for item in self._mappings.get(rule_id, ())
        )

    def technique_ids(self, rule_id: str) -> tuple[str, ...]:
        return tuple(
            str(item["technique_id"])
            for item in self._mappings.get(rule_id, ())
        )

    def validate_rule(
        self,
        rule_id: str,
        configured_ids: tuple[str, ...],
    ) -> None:
        mapped = self.technique_ids(rule_id)
        if tuple(configured_ids) != mapped:
            raise AnalysisError(
                f"MITRE mapping không khớp rule {rule_id}."
            )

    def _load(self) -> dict[str, tuple[dict[str, Any], ...]]:
        try:
            data = read_json_object(self.config_path)
        except JsonFileError as exc:
            raise AnalysisError(str(exc)) from exc
        if data.get("schema_version") != 1:
            raise AnalysisError(
                "mitre_mapping.json có schema_version không hỗ trợ."
            )
        mappings = data.get("mappings")
        if not isinstance(mappings, dict):
            raise AnalysisError("MITRE mappings phải là object.")
        result: dict[str, tuple[dict[str, Any], ...]] = {}
        for rule_id, items in mappings.items():
            if (
                not isinstance(rule_id, str)
                or not isinstance(items, list)
                or any(not isinstance(item, dict) for item in items)
            ):
                raise AnalysisError("MITRE mapping không hợp lệ.")
            for item in items:
                if not item.get("technique_id") or not item.get(
                    "technique_name"
                ):
                    raise AnalysisError(
                        f"MITRE mapping thiếu trường cho {rule_id}."
                    )
            result[rule_id] = tuple(dict(item) for item in items)
        return result
