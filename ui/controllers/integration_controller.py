"""Controller for external DFIR tool processing from the dashboard."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from integrations.integration_service import IntegrationService
from ui.controllers.case_controller import CaseController


class IntegrationController:
    def __init__(
        self,
        case_controller: CaseController,
        root: str | Path | None = None,
        *,
        service: IntegrationService | None = None,
        actor: str = "analyst",
    ) -> None:
        self.case_controller = case_controller
        self.service = service or IntegrationService(
            root,
            actor=actor,
        )

    def process(
        self,
        *,
        tool_ids: Iterable[str] | None = None,
        continue_on_error: bool = True,
        on_progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        result = self.service.process_case(
            case_id,
            tool_ids=tool_ids,
            continue_on_error=continue_on_error,
            **({"on_progress": on_progress} if on_progress is not None else {}),
        )
        return {
            "case_id": result.case_id,
            "requested_tools": list(result.requested_tools),
            "succeeded_tools": list(result.succeeded_tools),
            "skipped_tools": list(result.skipped_tools),
            "failed_tools": list(result.failed_tools),
            "parsed_record_count": result.parsed_record_count,
            "live_record_count": getattr(result, "live_record_count", 0),
            "normalized_count": result.normalized_count,
            "duplicate_count": result.duplicate_count,
            "timeline_count": result.timeline_count,
            "records_path": (
                str(result.records_path) if result.records_path is not None else None
            ),
            "timeline_path": (
                str(result.timeline_path) if result.timeline_path is not None else None
            ),
            "warnings": list(result.warnings),
        }
