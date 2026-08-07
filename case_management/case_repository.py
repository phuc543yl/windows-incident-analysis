"""JSON repository for isolated Case directories."""

from __future__ import annotations

import shutil
import threading
from pathlib import Path

from common.enums import CaseStatus
from common.exceptions import (
    CaseAlreadyExistsError,
    CaseClosedError,
    CaseNotFoundError,
    JsonFileError,
)
from common.json_utils import read_json_object, write_json
from common.paths import cases_dir, ensure_base_directories, project_root
from case_management.case_paths import CasePaths, get_case_paths
from models.case import Case
from models.collection_plan import CollectionPlan
from models.target_host import TargetHost


class CaseRepository:
    def __init__(self, root: str | Path | None = None) -> None:
        self.project = project_root(root)
        ensure_base_directories(self.project)
        self._lock = threading.RLock()

    def exists(self, case_id: str) -> bool:
        return self.paths(case_id).case_json.is_file()

    def paths(self, case_id: str) -> CasePaths:
        return get_case_paths(case_id, self.project)

    def create(
        self,
        case: Case,
        target: TargetHost,
        plan: CollectionPlan,
    ) -> CasePaths:
        if case.case_id != plan.case_id:
            raise ValueError("Case và CollectionPlan không cùng case_id.")
        if case.target_host_id != target.host_id:
            raise ValueError("Case và TargetHost không cùng target_host_id.")

        paths = self.paths(case.case_id)
        with self._lock:
            if paths.root.exists():
                raise CaseAlreadyExistsError(
                    f"Case đã tồn tại: {case.case_id}"
                )
            try:
                paths.create_layout()
                write_json(paths.case_json, case.to_dict())
                write_json(paths.target_json, target.to_dict())
                write_json(paths.collection_plan_json, plan.to_dict())
            except Exception:
                if paths.root.exists():
                    shutil.rmtree(paths.root)
                raise
        return paths

    def load_case(self, case_id: str) -> Case:
        paths = self._require_case(case_id)
        try:
            return Case.from_dict(read_json_object(paths.case_json))
        except JsonFileError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise JsonFileError(
                f"case.json của {case_id} không hợp lệ: {exc}"
            ) from exc

    def load_target(self, case_id: str) -> TargetHost:
        paths = self._require_case(case_id)
        try:
            return TargetHost.from_dict(read_json_object(paths.target_json))
        except JsonFileError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise JsonFileError(
                f"target.json của {case_id} không hợp lệ: {exc}"
            ) from exc

    def load_collection_plan(self, case_id: str) -> CollectionPlan:
        paths = self._require_case(case_id)
        try:
            return CollectionPlan.from_dict(
                read_json_object(paths.collection_plan_json)
            )
        except JsonFileError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise JsonFileError(
                f"collection_plan.json của {case_id} không hợp lệ: {exc}"
            ) from exc

    def save_case(self, case: Case) -> Path:
        paths = self._require_case(case.case_id)
        with self._lock:
            return write_json(paths.case_json, case.to_dict())

    def save_target(self, case_id: str, target: TargetHost) -> Path:
        paths = self._require_case(case_id)
        case = self.load_case(case_id)
        if case.target_host_id != target.host_id:
            raise ValueError("target.host_id không khớp với Case.")
        with self._lock:
            return write_json(paths.target_json, target.to_dict())

    def save_collection_plan(
        self,
        case_id: str,
        plan: CollectionPlan,
    ) -> Path:
        paths = self._require_case(case_id)
        if plan.case_id != case_id:
            raise ValueError("plan.case_id không khớp Case.")
        with self._lock:
            return write_json(paths.collection_plan_json, plan.to_dict())

    def list_cases(
        self,
        status: CaseStatus | str | None = None,
        *,
        strict: bool = False,
    ) -> list[Case]:
        status_filter = None
        if status is not None:
            try:
                status_filter = (
                    status
                    if isinstance(status, CaseStatus)
                    else CaseStatus(str(status))
                )
            except ValueError as exc:
                raise ValueError(f"Case status không hợp lệ: {status}") from exc

        results: list[Case] = []
        for directory in sorted(cases_dir(self.project).glob("CASE-*")):
            if not directory.is_dir():
                continue
            try:
                case = Case.from_dict(
                    read_json_object(directory / "case.json")
                )
            except (JsonFileError, KeyError, TypeError, ValueError):
                if strict:
                    raise
                continue
            if status_filter is None or case.status is status_filter:
                results.append(case)
        return sorted(results, key=lambda item: item.created_at, reverse=True)

    def require_open(self, case_id: str) -> Case:
        case = self.load_case(case_id)
        if case.status is CaseStatus.CLOSED:
            raise CaseClosedError(f"Case đã đóng: {case_id}")
        return case

    def _require_case(self, case_id: str) -> CasePaths:
        paths = self.paths(case_id)
        if not paths.case_json.is_file():
            raise CaseNotFoundError(f"Không tìm thấy Case: {paths.case_id}")
        return paths
