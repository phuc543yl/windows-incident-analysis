"""Controller for derived investigation views and analyst notebook."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from analysis.investigation.baseline import BaselineComparer
from analysis.investigation.checklist import ChecklistService
from analysis.investigation.entities import pivot_entities
from analysis.investigation.investigation_service import InvestigationService
from analysis.investigation.notes_service import NotesService
from common.json_utils import read_json_object, write_json
from evidence.integrity_verifier import VERIFICATION_FILENAME
from integrations.tool_registry import ToolRegistry
from integrations.tool_validator import ToolValidator
from processing.processing_pipeline import ProcessingPipeline
from ui.controllers.case_controller import CaseController


class InvestigateController:
    def __init__(
        self,
        case_controller: CaseController,
        root: str | Path | None = None,
        *,
        actor: str = "analyst",
    ) -> None:
        self.case_controller = case_controller
        self.investigation = InvestigationService(root, actor=actor)
        self.notes = NotesService(root, actor=actor)
        self.checklist = ChecklistService(root)
        self.baseline = BaselineComparer(root)
        self.pipeline = ProcessingPipeline(root)
        self.validator = ToolValidator(ToolRegistry(root))

    def load(self) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        view = self.investigation.load_view(case_id)
        checklist = self.checklist.load(case_id)
        verification_path = (
            self.investigation.repository.paths(case_id).analysis
            / VERIFICATION_FILENAME
        )
        return {
            **view,
            "notes": self.notes.load(case_id),
            "checklist": checklist.get("items", []),
            "integrity_verification": read_json_object(verification_path)
            if verification_path.is_file()
            else {},
        }

    def add_note(self, text: str) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        self.notes.add(case_id, text)
        return self.load()

    def capture_baseline(
        self, *, on_progress: Callable[[str], None] | None = None
    ) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        self.baseline.capture(case_id, on_progress=on_progress)
        records = self.pipeline.load_records(case_id)
        paths = self.investigation.repository.paths(case_id)
        write_json(
            paths.baseline_diff_json, self.baseline.compare(case_id, records).to_dict()
        )
        return self.load()

    def save_checklist(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        self.checklist.save(case_id, items)
        return self.load()

    def pivot(self, entity_type: str, value: str) -> list[dict[str, Any]]:
        case_id = self.case_controller.require_case_id()
        try:
            records = self.pipeline.load_records(case_id)
        except Exception:
            return []
        matched = pivot_entities(
            records,
            entity_type=entity_type,
            value=value,
        )
        return [record.to_dict() for record in matched]

    def tool_health(self) -> list[str]:
        lines: list[str] = []
        for result in self.validator.validate_all():
            state = "OK" if result.available else "THIẾU"
            lines.append(f"{result.tool_id}: {state}")
            lines.extend(f"  - {error}" for error in result.errors)
        return lines or ["Không đọc được cấu hình tool."]
