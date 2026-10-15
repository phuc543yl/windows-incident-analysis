"""Controller for Local/Agent collection execution."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from collection.collection_service import CollectionService
from ui.controllers.case_controller import CaseController


class CollectionController:
    def __init__(
        self,
        case_controller: CaseController,
        root: str | Path | None = None,
        *,
        service: CollectionService | None = None,
    ) -> None:
        self.case_controller = case_controller
        self.service = service or CollectionService(root)

    def collect(
        self,
        *,
        mode: str | None = None,
        agent_id: str | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> tuple[dict[str, Any], ...]:
        case_id = self.case_controller.require_case_id()
        results = self.service.collect_case(
            case_id,
            mode=mode,
            agent_id=agent_id,
            **({"on_progress": on_progress} if on_progress is not None else {}),
        )
        return tuple(result.to_dict() for result in results)

    @staticmethod
    def summarize(
        results: tuple[dict[str, Any], ...],
    ) -> dict[str, int]:
        succeeded = sum(
            result.get("status") in {"succeeded", "partial"} for result in results
        )
        failed = sum(result.get("status") == "failed" for result in results)
        return {
            "total": len(results),
            "succeeded": succeeded,
            "failed": failed,
        }

    def close(self) -> None:
        self.service.close()
