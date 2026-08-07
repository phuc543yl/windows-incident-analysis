"""Controller for Case lifecycle and shared Case selection."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from case_management.case_service import CaseService


class CaseController:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        service: CaseService | None = None,
        actor: str | None = None,
        on_case_changed: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.service = service or CaseService(root, actor=actor)
        self.on_case_changed = on_case_changed
        self.current_case_id: str | None = None
        self.current_context: dict[str, Any] | None = None

    def list_cases(self, status: str | None = None) -> tuple[dict[str, Any], ...]:
        return tuple(
            case.to_dict() for case in self.service.list_cases(status=status)
        )

    def create_case(self, **values: Any) -> dict[str, Any]:
        case = self.service.create_case(**values)
        return self.select_case(case.case_id)

    def select_case(self, case_id: str) -> dict[str, Any]:
        normalized = str(case_id).strip().upper()
        if not normalized:
            raise ValueError("case_id không được để trống.")
        context = self.service.get_case_context(normalized)
        self.current_case_id = context["case"]["case_id"]
        self.current_context = context
        self._notify(context)
        return context

    def refresh_current(self) -> dict[str, Any]:
        return self.select_case(self.require_case_id())

    def update_current(self, **changes: Any) -> dict[str, Any]:
        case_id = self.require_case_id()
        self.service.update_case(case_id, **changes)
        return self.select_case(case_id)

    def close_current(self, conclusion: str = "") -> dict[str, Any]:
        case_id = self.require_case_id()
        self.service.close_case(case_id, conclusion=conclusion)
        return self.select_case(case_id)

    def require_case_id(self) -> str:
        if self.current_case_id is None:
            from ui.controllers import CurrentCaseRequiredError

            raise CurrentCaseRequiredError(
                "Hãy tạo hoặc mở một Case trước khi thực hiện "
                "thao tác."
            )
        return self.current_case_id

    def clear_selection(self) -> None:
        self.current_case_id = None
        self.current_context = None

    def _notify(self, context: dict[str, Any]) -> None:
        if self.on_case_changed is not None:
            self.on_case_changed(context)
