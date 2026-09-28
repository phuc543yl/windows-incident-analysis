"""Load all Case-owned data needed by an investigation report."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.exceptions import JsonFileError, ReportError
from common.json_utils import read_json, read_json_object


@dataclass(frozen=True, slots=True)
class ReportContext:
    """Immutable snapshot used to generate every report format."""

    case: dict[str, Any]
    target: dict[str, Any]
    collection_plan: dict[str, Any]
    manifest: dict[str, Any]
    chain_of_custody: dict[str, Any]
    collection_runs: tuple[dict[str, Any], ...]
    tool_runs: tuple[dict[str, Any], ...]
    findings: tuple[dict[str, Any], ...]
    alerts: tuple[dict[str, Any], ...]
    incidents: tuple[dict[str, Any], ...]
    timeline: tuple[dict[str, Any], ...]
    story: tuple[dict[str, Any], ...]
    analyst_notes: tuple[dict[str, Any], ...]
    analyst_conclusion: dict[str, Any]
    recommendations: tuple[str, ...]

    @property
    def case_id(self) -> str:
        return str(self.case["case_id"])


class ReportContextBuilder:
    """Build a tolerant snapshot while rejecting corrupt Case-owned data."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.repository = CaseRepository(root)

    def build(self, case_id: str) -> ReportContext:
        case = self.repository.load_case(case_id)
        target = self.repository.load_target(case.case_id)
        plan = self.repository.load_collection_plan(case.case_id)
        paths = self.repository.paths(case.case_id)

        manifest = self._optional_object(
            paths.manifest_json,
            {
                "schema_version": 1,
                "case_id": case.case_id,
                "item_count": 0,
                "total_size_bytes": 0,
                "evidence_items": [],
            },
        )
        custody = self._optional_object(
            paths.chain_of_custody_json,
            {
                "schema_version": 1,
                "case_id": case.case_id,
                "entries": [],
            },
        )
        self._require_case_id(manifest, case.case_id, paths.manifest_json)
        self._require_case_id(
            custody,
            case.case_id,
            paths.chain_of_custody_json,
        )

        return ReportContext(
            case=case.to_dict(),
            target=target.to_dict(),
            collection_plan=plan.to_dict(),
            manifest=manifest,
            chain_of_custody=custody,
            collection_runs=self._read_jsonl(
                paths.collection_log,
                case.case_id,
            ),
            tool_runs=self._read_jsonl(
                paths.tool_runs_log,
                case.case_id,
            ),
            findings=self._read_envelope(
                paths.findings_json,
                "findings",
                case.case_id,
            ),
            alerts=self._read_envelope(
                paths.alerts_json,
                "alerts",
                case.case_id,
            ),
            incidents=self._read_envelope(
                paths.incidents_json,
                "incidents",
                case.case_id,
            ),
            timeline=self._read_envelope(
                paths.timeline_json,
                "timeline",
                case.case_id,
            ),
            story=self._read_envelope(
                paths.story_json,
                "milestones",
                case.case_id,
            )
            if paths.story_json.is_file()
            else (),
            analyst_notes=self._read_notes(paths.notes_json, case.case_id),
            analyst_conclusion=self._read_conclusion(
                paths.conclusion_json,
                case.case_id,
            ),
            recommendations=self._read_recommendations(
                paths.recommendations_json,
                case.case_id,
            ),
        )

    def _optional_object(
        self,
        path: Path,
        default: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            return read_json_object(path, default=default)
        except JsonFileError as exc:
            raise ReportError(str(exc)) from exc

    def _read_envelope(
        self,
        path: Path,
        key: str,
        case_id: str,
    ) -> tuple[dict[str, Any], ...]:
        if not path.exists():
            return ()
        data = self._optional_object(path, {})
        self._require_case_id(data, case_id, path)
        items = data.get(key)
        if items is None and key == "timeline":
            items = data.get("events")
        if not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ReportError(f"{path.name} phải có {key} là danh sách object.")
        return tuple(dict(item) for item in items)

    def _read_jsonl(
        self,
        path: Path,
        case_id: str,
    ) -> tuple[dict[str, Any], ...]:
        if not path.exists():
            return ()
        records: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ReportError(
                            f"{path.name} lỗi tại dòng {line_number}: "
                            f"{exc.msg}"
                        ) from exc
                    if not isinstance(record, dict):
                        raise ReportError(
                            f"{path.name} dòng {line_number} phải là object."
                        )
                    self._require_case_id(record, case_id, path)
                    records.append(record)
        except OSError as exc:
            raise ReportError(f"Không thể đọc {path}: {exc}") from exc
        return tuple(records)

    def _read_notes(
        self,
        path: Path,
        case_id: str,
    ) -> tuple[dict[str, Any], ...]:
        if not path.exists():
            return ()
        data = self._optional_object(path, {})
        self._require_case_id(data, case_id, path)
        notes = data.get("notes", data.get("entries", []))
        if not isinstance(notes, list):
            raise ReportError(f"{path.name} phải có notes là danh sách.")
        normalized: list[dict[str, Any]] = []
        for index, note in enumerate(notes, start=1):
            if isinstance(note, str):
                normalized.append({"text": note})
            elif isinstance(note, dict):
                normalized.append(dict(note))
            else:
                raise ReportError(
                    f"{path.name} có note #{index} không hợp lệ."
                )
        return tuple(normalized)

    def _read_conclusion(
        self,
        path: Path,
        case_id: str,
    ) -> dict[str, Any]:
        if not path.exists():
            return {}
        data = self._optional_object(path, {})
        self._require_case_id(data, case_id, path)
        return data

    def _read_recommendations(
        self,
        path: Path,
        case_id: str,
    ) -> tuple[str, ...]:
        if not path.exists():
            return ()
        try:
            data = read_json(path)
        except JsonFileError as exc:
            raise ReportError(str(exc)) from exc
        values: Any
        if isinstance(data, dict):
            self._require_case_id(data, case_id, path)
            values = data.get("recommendations", [])
        else:
            values = data
        if not isinstance(values, list):
            raise ReportError(
                f"{path.name} phải là danh sách hoặc có recommendations."
            )
        result = tuple(
            str(value).strip()
            for value in values
            if str(value).strip()
        )
        if len(result) != len(values):
            raise ReportError(
                f"{path.name} chứa khuyến nghị rỗng hoặc không hợp lệ."
            )
        return result

    @staticmethod
    def _require_case_id(
        data: dict[str, Any],
        case_id: str,
        path: Path,
    ) -> None:
        value = data.get("case_id")
        if value != case_id:
            raise ReportError(
                f"{path.name} không khớp Case {case_id}."
            )
