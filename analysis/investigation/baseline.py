"""Compare baseline and after-event artifacts inside one Case."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from analysis.helpers import attribute, file_hashes, service_name
from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.enums import ArtifactType
from common.exceptions import AnalysisError
from common.json_utils import read_json, read_json_object, write_json
from common.time_utils import utc_now_iso
from evidence.evidence_service import EvidenceService
from models import new_id
from models.normalized_record import NormalizedRecord
from processing.processing_pipeline import ProcessingPipeline


@dataclass(frozen=True, slots=True)
class BaselineChange:
    category: str
    identifier: str
    before: str
    after: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "identifier": self.identifier,
            "before": self.before,
            "after": self.after,
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class BaselineDiff:
    case_id: str
    change_count: int
    changes: tuple[BaselineChange, ...]
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "change_count": self.change_count,
            "changes": [item.to_dict() for item in self.changes],
            "notes": list(self.notes),
        }


class BaselineComparer:
    def __init__(self, root: str | Path | None = None) -> None:
        self.repository = CaseRepository(root)

    def capture(
        self,
        case_id: str,
        *,
        on_progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Save a new T0 state and an evidence bundle without replacing T0."""
        report = on_progress or (lambda _message: None)
        case = self.repository.require_open(case_id)
        paths = self.repository.paths(case.case_id)
        report("Đang kiểm tra SHA-256 trước khi lưu baseline T0...")
        evidence = EvidenceService(self.repository.project)
        evidence.verify_case(case.case_id)
        pipeline = ProcessingPipeline(self.repository.project)
        pipeline.verify_source_binding(case.case_id)
        records = pipeline.load_records(case.case_id)
        if not records:
            raise AnalysisError("Hãy xử lý dữ liệu thô trước khi lưu baseline T0.")
        snapshot_id = new_id("BASELINE")
        report("Đang lưu bản sao bằng chứng của baseline T0...")
        bundle = evidence.build_bundle(
            case.case_id,
            output_name=f"{snapshot_id}.zip",
        )
        report("Đang lưu trạng thái dịch vụ, file, Registry và Scheduled Task...")
        payload = {
            "schema_version": 1,
            "case_id": case.case_id,
            "snapshot_id": snapshot_id,
            "captured_at": utc_now_iso(),
            "record_count": len(records),
            "records": [record.to_dict() for record in records],
            "states": _snapshot_states(records, paths.raw / "Files"),
            "evidence_bundle": bundle.bundle_path.relative_to(paths.root).as_posix(),
            "evidence_bundle_sha256": bundle.sha256,
        }
        snapshot_path = paths.analysis / "baselines" / f"{snapshot_id}.json"
        write_json(snapshot_path, payload)
        snapshot_path.with_suffix(".sha256").write_text(
            _sha256(snapshot_path), encoding="ascii"
        )
        AuditLogger(case.case_id, self.repository.project).log(
            "baseline_captured",
            actor=evidence.actor,
            details={
                "snapshot_id": snapshot_id,
                "record_count": len(records),
                "evidence_bundle_sha256": bundle.sha256,
            },
        )
        report(f"Đã lưu baseline T0: {snapshot_id} ({len(records)} bản ghi).")
        return payload

    def latest(self, case_id: str) -> dict[str, Any]:
        paths = self.repository.paths(case_id)
        candidates: list[dict[str, Any]] = []
        for path in (paths.analysis / "baselines").glob("BASELINE-*.json"):
            checksum_path = path.with_suffix(".sha256")
            if not checksum_path.is_file() or checksum_path.read_text(
                encoding="ascii"
            ).strip() != _sha256(path):
                raise AnalysisError(f"Baseline không khớp SHA-256: {path.name}")
            snapshot = read_json_object(path)
            if snapshot.get("case_id") != paths.case_id or not isinstance(
                snapshot.get("states"), dict
            ):
                raise AnalysisError(f"Baseline không hợp lệ: {path.name}")
            candidates.append(snapshot)
        return max(candidates, key=lambda item: item["captured_at"], default={})

    def compare(
        self,
        case_id: str,
        records: tuple[NormalizedRecord, ...] = (),
    ) -> BaselineDiff:
        case = self.repository.load_case(case_id)
        paths = self.repository.paths(case.case_id)
        changes: list[BaselineChange] = []
        notes: list[str] = []
        changes.extend(_record_hash_changes(records))
        changes.extend(_record_service_changes(records))
        snapshot = self.latest(case.case_id)
        if snapshot:
            current = _snapshot_states(records, paths.raw / "Files")
            for category, before_items in snapshot["states"].items():
                if category not in current:
                    notes.append(f"Chưa có dữ liệu T1 cho nhóm {category}.")
                    continue
                after_items = current[category]
                for identifier in sorted(set(before_items) | set(after_items)):
                    before = before_items.get(identifier, "(không quan sát thấy)")
                    after = after_items.get(identifier, "(không quan sát thấy)")
                    if before != after:
                        changes.append(
                            BaselineChange(
                                category=category,
                                identifier=identifier,
                                before=before,
                                after=after,
                                summary=f"{identifier} thay đổi so với baseline T0.",
                            )
                        )
            notes.append(
                f"Đối chiếu với T0 {snapshot['snapshot_id']} ({snapshot['captured_at']})."
            )
        else:
            notes.append(
                "Chưa lưu baseline T0; chỉ đối chiếu các cặp trước/sau có sẵn."
            )
        file_changes, file_notes = _paired_file_hashes(paths.raw / "Files")
        changes.extend(file_changes)
        notes.extend(file_notes)
        unique = tuple(
            sorted(
                set(changes),
                key=lambda item: (item.category, item.identifier, item.summary),
            )
        )
        return BaselineDiff(
            case_id=case.case_id,
            change_count=len(unique),
            changes=unique,
            notes=tuple(notes),
        )


def _record_hash_changes(
    records: tuple[NormalizedRecord, ...],
) -> list[BaselineChange]:
    changes: list[BaselineChange] = []
    for record in records:
        before, after = file_hashes(record)
        if before and after and before != after:
            path = record.file_path or record.record_id
            changes.append(
                BaselineChange(
                    category="file_hash",
                    identifier=path,
                    before=before,
                    after=after,
                    summary=f"SHA-256 của {path} đã đổi.",
                )
            )
    return changes


def _record_service_changes(
    records: tuple[NormalizedRecord, ...],
) -> list[BaselineChange]:
    before_state: dict[tuple[str, str], str] = {}
    after_state: dict[tuple[str, str], str] = {}
    for record in records:
        name = service_name(record)
        if not name:
            continue
        role = str(
            record.attributes.get("snapshot")
            or record.attributes.get("baseline_role")
            or ""
        ).casefold()
        state = str(
            record.attributes.get("State")
            or record.attributes.get("status")
            or record.attributes.get("StartType")
            or ""
        ).strip()
        key = (record.hostname.casefold(), name.casefold())
        if role in {"before", "baseline"} and state:
            before_state[key] = state
        elif role in {"after", "current"} and state:
            after_state[key] = state
    changes: list[BaselineChange] = []
    for key in sorted(set(before_state) | set(after_state)):
        before = before_state.get(key, "")
        after = after_state.get(key, "")
        hostname, name = key
        if before and after and before.casefold() != after.casefold():
            changes.append(
                BaselineChange(
                    category="service",
                    identifier=f"{hostname}:{name}",
                    before=before,
                    after=after,
                    summary=f"Dịch vụ {name}: {before} → {after}.",
                )
            )
    return changes


def _snapshot_states(
    records: tuple[NormalizedRecord, ...],
    files_dir: Path,
) -> dict[str, dict[str, str]]:
    states: dict[str, dict[str, str]] = {}
    for record in sorted(records, key=lambda item: item.timestamp):
        category = ""
        identifier = ""
        value: Any = ""
        if record.artifact_type is ArtifactType.SERVICES:
            category = "service"
            identifier = service_name(record)
            value = {
                "state": str(attribute(record, "State", "status")).strip().casefold(),
                "start_mode": str(
                    attribute(record, "StartMode", "start_mode", "StartType")
                )
                .strip()
                .casefold(),
                "path": str(
                    attribute(
                        record, "path_name", "ImagePath", default=record.file_path
                    )
                )
                .replace("\\", "/")
                .casefold(),
            }
        elif record.artifact_type is ArtifactType.REGISTRY:
            category = "registry"
            identifier = record.file_path or str(
                attribute(record, "KeyPath", "registry_key")
            )
            value = attribute(record, "Data", "value_data", "value")
        elif record.artifact_type is ArtifactType.SCHEDULED_TASKS:
            category = "scheduled_task"
            identifier = str(
                attribute(record, "TaskName", "TaskPath", default=record.file_path)
            )
            value = attribute(record, "TaskContent", "TaskXml", "Action", "actions")
        elif record.artifact_type is ArtifactType.FILES:
            category = "file_hash"
            identifier = record.file_path
            value = attribute(
                record, "sha256", "current_sha256", "hash_after", "sha256_after"
            )
        if category and identifier and value not in (None, ""):
            normalized_identifier = identifier.replace("\\", "/").casefold()
            key = f"{record.hostname.casefold()}:{normalized_identifier}"
            states.setdefault(category, {})[key] = (
                json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
                if not isinstance(value, str)
                else value
            )
    if files_dir.is_dir():
        states["collected_file_hash"] = {
            path.name.casefold(): _sha256(path)
            for path in sorted(files_dir.iterdir())
            if path.is_file() and not path.is_symlink()
        }
    return states


def _paired_file_hashes(
    files_dir: Path,
) -> tuple[list[BaselineChange], list[str]]:
    if not files_dir.is_dir():
        return [], []
    pairs: dict[str, dict[str, Path]] = {}
    for path in files_dir.iterdir():
        if not path.is_file() or path.is_symlink():
            continue
        stem = path.stem.casefold()
        match = re.fullmatch(r"(.+)[_.-](before|after)", stem)
        if match:
            key = match.group(1) + path.suffix.casefold()
            pairs.setdefault(key, {})[match.group(2)] = path
    changes: list[BaselineChange] = []
    notes: list[str] = []
    for key, sides in sorted(pairs.items()):
        if "before" not in sides or "after" not in sides:
            continue
        before_hash = _sha256(sides["before"])
        after_hash = _sha256(sides["after"])
        if before_hash == after_hash:
            notes.append(f"{key}: hash trước/sau giống nhau.")
            continue
        changes.append(
            BaselineChange(
                category="file_hash",
                identifier=key,
                before=before_hash,
                after=after_hash,
                summary=f"Cặp file {key} có SHA-256 khác nhau.",
            )
        )
    return changes, notes


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_optional_json(path: Path) -> Any:
    if not path.is_file():
        return None
    return read_json(path)
