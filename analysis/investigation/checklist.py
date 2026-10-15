"""Profile-specific investigation checklist stored on the Case."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.exceptions import AnalysisError
from common.json_utils import read_json_object, write_json
from common.paths import config_dir

DEFAULT_ITEMS = {
    "general_investigation": (
        "Đã nêu giả thuyết trước khi xem Alert",
        "Đã thu evidence phù hợp profile",
        "Đã verify SHA-256",
        "Đã loại trừ hoạt động bảo trì hợp lệ",
        "Đã có bằng chứng CIA trước khi Confirmed",
    ),
    "account_compromise": (
        "Đã đối chiếu 4625 và 4624 cùng user/IP",
        "Đã loại trừ quên mật khẩu hoặc scanner nội bộ",
        "Đã kiểm tra hoạt động sau đăng nhập",
        "Đã verify hash Security log",
    ),
    "endpoint_compromise": (
        "Đã kiểm tra parent process / command line",
        "Đã thu Prefetch/Registry/Task liên quan",
        "Đã so hash file trước/sau nếu có",
        "Đã loại trừ công cụ quản trị hợp lệ",
    ),
    "log_tampering": (
        "Đã ghi nhận Event 1102/1100",
        "Đã so số event Security trước/sau",
        "Đã xác định actor và lịch bảo trì",
        "Đã bảo toàn EVTX còn lại",
    ),
    "service_disruption": (
        "Đã có baseline service running",
        "Đã đối chiếu 7036/7040",
        "Đã probe Availability sau sự kiện",
        "Đã loại trừ Windows Update / change window",
    ),
}


class ChecklistService:
    def __init__(self, root: str | Path | None = None) -> None:
        self.repository = CaseRepository(root)

    def load(self, case_id: str) -> dict[str, Any]:
        case = self.repository.load_case(case_id)
        path = self.repository.paths(case.case_id).checklist_json
        expected = self._items_for(case.profile_id)
        saved: dict[str, bool] = {}
        if path.is_file():
            payload = read_json_object(path)
            if payload.get("case_id") != case.case_id:
                raise AnalysisError("Checklist không khớp Case.")
            self._validate_items(payload.get("items"))
            saved = {item["text"]: item["done"] for item in payload["items"]}
        items = [{"text": text, "done": saved.get(text, False)} for text in expected]
        return {
            "schema_version": 1,
            "case_id": case.case_id,
            "profile_id": case.profile_id,
            "items": items,
        }

    def save(
        self,
        case_id: str,
        items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        case = self.repository.require_open(case_id)
        self._validate_items(items)
        expected = self._items_for(case.profile_id)
        if {item["text"] for item in items} != set(expected):
            raise AnalysisError("Checklist phải có đầy đủ các mục của profile.")
        payload = {
            "schema_version": 1,
            "case_id": case.case_id,
            "profile_id": case.profile_id,
            "items": items,
        }
        write_json(self.repository.paths(case.case_id).checklist_json, payload)
        return payload

    def require_complete(self, case_id: str) -> None:
        items = self.load(case_id)["items"]
        pending = [item["text"] for item in items if item["done"] is not True]
        if not items or pending:
            raise AnalysisError(
                "Hãy hoàn thành và lưu checklist trước khi Confirmed. "
                + "; ".join(pending)
            )

    @staticmethod
    def _validate_items(items: Any) -> None:
        if not isinstance(items, list) or not items:
            raise AnalysisError("Checklist phải có danh sách mục không rỗng.")
        seen: set[str] = set()
        for item in items:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("text"), str)
                or not item["text"].strip()
                or not isinstance(item.get("done"), bool)
                or item["text"] in seen
            ):
                raise AnalysisError("Mục checklist không hợp lệ hoặc trùng lặp.")
            seen.add(item["text"])

    def _items_for(self, profile_id: str) -> tuple[str, ...]:
        configured = config_dir(self.repository.project) / (
            "investigation_checklists.json"
        )
        if configured.is_file():
            data = read_json_object(configured)
            profiles = data.get("profiles", {})
            if isinstance(profiles, dict) and profile_id in profiles:
                values = profiles[profile_id]
                if isinstance(values, list) and values:
                    return tuple(str(item) for item in values)
        return DEFAULT_ITEMS.get(profile_id, DEFAULT_ITEMS["general_investigation"])
