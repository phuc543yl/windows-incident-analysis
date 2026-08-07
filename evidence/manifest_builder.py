"""Create evidence metadata, SHA-256 list, and chain-of-custody records."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from case_management.case_paths import RAW_ARTIFACT_DIRECTORIES
from case_management.case_repository import CaseRepository
from common.enums import ArtifactType, EvidenceCategory
from common.exceptions import EvidenceError, JsonFileError
from common.json_utils import read_json_object, write_json
from common.time_utils import utc_now_iso
from evidence.hash_calculator import HashCalculator
from models.evidence_item import EvidenceItem, stable_evidence_id
from models.evidence_manifest import EvidenceManifest

_RAW_DIRECTORY_TO_ARTIFACT = {
    directory_name.casefold(): artifact_id
    for artifact_id, directory_name in RAW_ARTIFACT_DIRECTORIES.items()
}


class ManifestBuilder:
    def __init__(
        self,
        case_id: str,
        root: str | Path | None = None,
        *,
        calculator: HashCalculator | None = None,
    ) -> None:
        self.repository = CaseRepository(root)
        self.case_id = self.repository.paths(case_id).case_id
        self.paths = self.repository.paths(self.case_id)
        self.calculator = calculator or HashCalculator()

    def discover_files(self) -> tuple[Path, ...]:
        files: list[Path] = []
        for evidence_root in (self.paths.live, self.paths.raw):
            for path in evidence_root.rglob("*"):
                if path.is_symlink():
                    raise EvidenceError(
                        f"Evidence không được là symbolic link: {path}"
                    )
                if path.is_file():
                    files.append(path.resolve())
        return tuple(
            sorted(
                files,
                key=lambda item: item.relative_to(
                    self.paths.root
                ).as_posix().casefold(),
            )
        )

    def build(
        self,
        *,
        collected_by: str,
        source_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        case = self.repository.load_case(self.case_id)
        target = self.repository.load_target(self.case_id)
        files = self.discover_files()
        if not files:
            raise EvidenceError(
                f"Case {self.case_id} chưa có evidence để tạo manifest."
            )
        actor = collected_by.strip() if collected_by.strip() else case.created_by
        if not actor:
            actor = "unknown"
        normalized_sources = {
            _portable_relative(key): value
            for key, value in (source_map or {}).items()
        }

        items: list[EvidenceItem] = []
        for path in files:
            stored_path = path.relative_to(self.paths.root).as_posix()
            category, artifact_type, collector_id = self._classify(path)
            hash_result = self.calculator.calculate(path)
            stat = path.stat()
            source_path = normalized_sources.get(stored_path, stored_path)
            evidence_id = stable_evidence_id(
                self.case_id,
                stored_path,
                hash_result.sha256,
            )
            items.append(
                EvidenceItem(
                    case_id=self.case_id,
                    evidence_id=evidence_id,
                    artifact_type=artifact_type,
                    category=category,
                    source_path=source_path,
                    stored_path=stored_path,
                    collector_id=collector_id,
                    hostname=target.hostname,
                    sha256=hash_result.sha256,
                    size_bytes=hash_result.size_bytes,
                    collected_at=datetime.fromtimestamp(
                        stat.st_mtime,
                        tz=timezone.utc,
                    ),
                    metadata={
                        "collected_by": actor,
                        "source_path_inferred": stored_path
                        not in normalized_sources,
                    },
                )
            )

        generated_at = utc_now_iso()
        manifest = EvidenceManifest(
            case_id=self.case_id,
            generated_by=actor,
            generated_at=generated_at,
            evidence_items=tuple(items),
        ).to_dict()
        write_json(self.paths.manifest_json, manifest)
        self._write_hash_list(items)
        self._update_chain_of_custody(items, actor, generated_at)
        return manifest

    def _classify(
        self,
        path: Path,
    ) -> tuple[EvidenceCategory, ArtifactType, str]:
        relative = path.relative_to(self.paths.acquisition)
        if relative.parts[0].casefold() == "live":
            collector_id = path.stem.lower()
            try:
                artifact_type = ArtifactType(collector_id)
            except ValueError as exc:
                raise EvidenceError(
                    f"Không xác định live artifact type: {path.name}"
                ) from exc
            return (
                EvidenceCategory.LIVE,
                artifact_type,
                collector_id,
            )

        if (
            len(relative.parts) < 3
            or relative.parts[0].casefold() != "raw"
        ):
            raise EvidenceError(
                f"Evidence nằm sai cấu trúc acquisition: {path}"
            )
        directory_name = relative.parts[1].casefold()
        try:
            collector_id = _RAW_DIRECTORY_TO_ARTIFACT[directory_name]
            artifact_type = ArtifactType(collector_id)
        except (KeyError, ValueError) as exc:
            raise EvidenceError(
                f"Không xác định raw artifact type: {path}"
            ) from exc
        return (
            EvidenceCategory.RAW_ARTIFACT,
            artifact_type,
            collector_id,
        )

    def _write_hash_list(self, items: list[EvidenceItem]) -> None:
        content = "".join(
            f"{item.sha256}  {item.stored_path}\n"
            for item in items
        )
        _atomic_write_text(self.paths.hashes_sha256, content)

    def _update_chain_of_custody(
        self,
        items: list[EvidenceItem],
        actor: str,
        timestamp: str,
    ) -> None:
        if self.paths.chain_of_custody_json.exists():
            try:
                custody = read_json_object(
                    self.paths.chain_of_custody_json
                )
            except JsonFileError as exc:
                raise EvidenceError(str(exc)) from exc
            if custody.get("case_id") != self.case_id:
                raise EvidenceError(
                    "chain_of_custody.json không khớp Case."
                )
            entries = custody.get("entries")
            if not isinstance(entries, list):
                raise EvidenceError(
                    "chain_of_custody.json có entries không hợp lệ."
                )
        else:
            custody = {
                "schema_version": 1,
                "case_id": self.case_id,
                "entries": [],
            }
            entries = custody["entries"]

        registered_ids = {
            entry.get("evidence_id")
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("action") == "evidence_registered"
        }
        for item in items:
            if item.evidence_id in registered_ids:
                continue
            entries.append(
                {
                    "timestamp": timestamp,
                    "action": "evidence_registered",
                    "actor": actor,
                    "evidence_id": item.evidence_id,
                    "stored_path": item.stored_path,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                    "collector_id": item.collector_id,
                    "hostname": item.hostname,
                }
            )
        custody["updated_at"] = timestamp
        write_json(self.paths.chain_of_custody_json, custody)


def _portable_relative(value: str) -> str:
    raw = str(value).replace("\\", "/")
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or ".." in path.parts
        or (path.parts and ":" in path.parts[0])
    ):
        raise ValueError(f"Đường dẫn source_map không hợp lệ: {value}")
    return path.as_posix()


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
