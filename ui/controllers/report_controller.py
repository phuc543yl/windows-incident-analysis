"""Controller for multi-format report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from reporting.report_service import ReportService
from ui.controllers.case_controller import CaseController


class ReportController:
    def __init__(
        self,
        case_controller: CaseController,
        root: str | Path | None = None,
        *,
        service: ReportService | None = None,
        actor: str = "analyst",
    ) -> None:
        self.case_controller = case_controller
        self.service = service or ReportService(root, actor=actor)

    def generate(
        self,
        formats: Iterable[str],
    ) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        result = self.service.generate(case_id, formats=formats)
        return {
            "case_id": result.case_id,
            "formats": list(result.formats),
            "output_paths": {
                report_format: str(path)
                for report_format, path in result.output_paths.items()
            },
        }
