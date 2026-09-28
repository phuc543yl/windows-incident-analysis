"""Profile-specific investigation checklist stored on the Case."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
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
        if path.is_file():
            return read_json_object(path)
        items = [
            {"text": text, "done": False}
            for text in self._items_for(case.profile_id)
        ]
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
        payload = {
            "schema_version": 1,
            "case_id": case.case_id,
            "profile_id": case.profile_id,
            "items": items,
        }
        write_json(self.repository.paths(case.case_id).checklist_json, payload)
        return payload

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
