"""Safely import evidence collected by a remote Agent into a Case."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.exceptions import CollectionError
from evidence.bundle_reader import BundleReader
from evidence.hash_calculator import HashCalculator
from evidence.manifest_builder import ManifestBuilder
from models.evidence_item import EvidenceItem
from models.evidence_manifest import EvidenceManifest

_SAFE_TASK_PATTERN = re.compile(r"[^A-Za-z0-9_.-]")


@dataclass(frozen=True, slots=True)
class AgentBundleImportResult:
    """Summary of evidence imported from one Agent bundle."""

    case_id: str
    bundle_path: Path
    bundle_sha256: str
    imported_paths: tuple[str, ...]
    reused_paths: tuple[str, ...]
    manifest_path: Path

    @property
    def item_count(self) -> int:
        return len(self.imported_paths) + len(self.reused_paths)


class AgentBundleImporter:
    """Verify an Agent bundle and merge only its evidence into a Case."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.actor = actor.strip() or "analyst"
        self.calculator = HashCalculator()

    def import_bundle(
        self,
        case_id: str,
        bundle_path: str | Path,
        *,
        expected_sha256: str | None = None,
        task_id: str = "agent-task",
        agent_id: str = "agent",
    ) -> AgentBundleImportResult:
        case = self.repository.require_open(case_id)
        paths = self.repository.paths(case.case_id)
        reader = BundleReader(bundle_path)
        verification = reader.verify(expected_sha256=expected_sha256)
        raw_manifest = reader.read_manifest()
        try:
            manifest = EvidenceManifest.from_dict(raw_manifest)
        except (KeyError, TypeError, ValueError) as exc:
            raise CollectionError(
                f"Schema manifest của Agent không hợp lệ: {exc}"
            ) from exc
        if manifest.case_id != case.case_id:
            raise CollectionError(
                "Agent Bundle không khớp Case đang thu thập."
            )
        if not manifest.evidence_items:
            raise CollectionError(
                "Manifest của Agent Bundle không có evidence_items hợp lệ."
            )

        safe_task_id = _SAFE_TASK_PATTERN.sub("_", task_id.strip())
        safe_task_id = safe_task_id or "agent-task"
        imported: list[str] = []
        reused: list[str] = []
        source_map: dict[str, str] = {}

        with tempfile.TemporaryDirectory(
            prefix="agent-import-",
            dir=paths.bundles,
        ) as temporary_directory:
            extracted_root = reader.extract(temporary_directory)
            validated = self._validate_items(
                manifest.evidence_items,
                extracted_root,
            )
            for item, source in validated:
                original_path = item.stored_path
                expected_hash = item.sha256 or ""
                destination, was_reused = self._destination_for(
                    paths.root,
                    original_path,
                    expected_hash,
                    safe_task_id,
                )
                stored_path = destination.relative_to(paths.root).as_posix()
                if was_reused:
                    reused.append(stored_path)
                else:
                    self._copy_new_file(source, destination)
                    imported.append(stored_path)
                source_map[stored_path] = item.source_path

        canonical_manifest = ManifestBuilder(
            case.case_id,
            self.repository.project,
        ).build(
            collected_by=agent_id.strip() or self.actor,
            source_map=source_map,
        )
        AuditLogger(case.case_id, self.repository.project).log(
            "agent_bundle_imported",
            actor=self.actor,
            details={
                "task_id": task_id,
                "agent_id": agent_id,
                "bundle_path": Path(bundle_path)
                .resolve()
                .relative_to(paths.root)
                .as_posix(),
                "bundle_sha256": verification["sha256"],
                "imported_count": len(imported),
                "reused_count": len(reused),
                "evidence_item_count": canonical_manifest["item_count"],
            },
        )
        return AgentBundleImportResult(
            case_id=case.case_id,
            bundle_path=reader.bundle_path,
            bundle_sha256=verification["sha256"],
            imported_paths=tuple(imported),
            reused_paths=tuple(reused),
            manifest_path=paths.manifest_json,
        )

    def _validate_items(
        self,
        items: tuple[EvidenceItem, ...],
        extracted_root: Path,
    ) -> tuple[tuple[EvidenceItem, Path], ...]:
        result: list[tuple[EvidenceItem, Path]] = []
        seen: set[str] = set()
        for index, item in enumerate(items, start=1):
            raw_path = item.stored_path
            relative = PurePosixPath(raw_path)
            if not self._is_evidence_path(relative):
                raise CollectionError(
                    f"Agent Bundle chứa evidence path không hợp lệ: {raw_path}"
                )
            normalized = relative.as_posix().casefold()
            if normalized in seen:
                raise CollectionError(
                    f"Manifest Agent chứa evidence trùng lặp: {raw_path}"
                )
            seen.add(normalized)

            expected_hash = item.sha256
            if expected_hash is None:
                raise CollectionError(
                    f"Evidence item #{index} có SHA-256 không hợp lệ."
                )
            source = extracted_root.joinpath(*relative.parts)
            if not source.is_file() or source.is_symlink():
                raise CollectionError(
                    f"Agent Bundle thiếu evidence đã khai báo: {raw_path}"
                )
            calculated = self.calculator.calculate(source)
            if calculated.sha256 != expected_hash.lower():
                raise CollectionError(
                    f"SHA-256 evidence trong Agent Bundle không khớp: {raw_path}"
                )
            if calculated.size_bytes != item.size_bytes:
                raise CollectionError(
                    f"Kích thước evidence trong Agent Bundle không khớp: {raw_path}"
                )
            result.append((item, source))
        return tuple(result)

    @staticmethod
    def _is_evidence_path(path: PurePosixPath) -> bool:
        if path.is_absolute() or ".." in path.parts or ":" in path.parts[0]:
            return False
        if len(path.parts) < 3 or path.parts[0].casefold() != "acquisition":
            return False
        category = path.parts[1].casefold()
        if category == "live":
            return len(path.parts) >= 3
        return category == "raw" and len(path.parts) >= 4

    def _destination_for(
        self,
        case_root: Path,
        original_path: str,
        expected_hash: str,
        task_id: str,
    ) -> tuple[Path, bool]:
        relative = PurePosixPath(original_path)
        desired = case_root.joinpath(*relative.parts).resolve()
        if not desired.exists():
            return desired, False
        if desired.is_file() and not desired.is_symlink():
            if self.calculator.calculate(desired).sha256 == expected_hash:
                return desired, True

        destination = (
            desired.parent
            / "_agent_imports"
            / task_id
            / desired.name
        ).resolve()
        if destination.exists():
            if (
                destination.is_file()
                and not destination.is_symlink()
                and self.calculator.calculate(destination).sha256
                == expected_hash
            ):
                return destination, True
            raise CollectionError(
                "Đã có evidence khác nội dung tại vị trí import của task: "
                f"{destination.name}"
            )
        return destination, False

    @staticmethod
    def _copy_new_file(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.part")
        if temporary.exists():
            raise CollectionError(
                f"Đang có file import tạm chưa hoàn tất: {temporary.name}"
            )
        try:
            shutil.copy2(source, temporary)
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
