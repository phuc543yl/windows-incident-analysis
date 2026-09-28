"""Compare baseline and after-event artifacts inside one Case."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.json_utils import read_json
from models.normalized_record import NormalizedRecord
from analysis.helpers import file_hashes, service_name


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
        file_changes, file_notes = _paired_file_hashes(paths.raw / "Files")
        changes.extend(file_changes)
        notes.extend(file_notes)
        unique = tuple(
            sorted(
                changes,
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
    before_state: dict[str, str] = {}
    after_state: dict[str, str] = {}
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
        if role in {"before", "baseline"} and state:
            before_state[name.casefold()] = state
        elif role in {"after", "current"} and state:
            after_state[name.casefold()] = state
    changes: list[BaselineChange] = []
    for name in sorted(set(before_state) | set(after_state)):
        before = before_state.get(name, "")
        after = after_state.get(name, "")
        if before and after and before.casefold() != after.casefold():
            changes.append(
                BaselineChange(
                    category="service",
                    identifier=name,
                    before=before,
                    after=after,
                    summary=f"Dịch vụ {name}: {before} → {after}.",
                )
            )
    return changes


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
        role = ""
        key = stem
        for token in ("_before", "-before", ".before"):
            if stem.endswith(token.lstrip(".-_")) or token in stem:
                if stem.endswith("before"):
                    role = "before"
                    key = stem[: -len("before")].rstrip("-_.")
                    break
        if not role:
            for token in ("_after", "-after", ".after"):
                if stem.endswith("after"):
                    role = "after"
                    key = stem[: -len("after")].rstrip("-_.")
                    break
        if role:
            pairs.setdefault(key, {})[role] = path
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
