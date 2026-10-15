"""Verify evidence files against manifest.json and hashes.sha256."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from case_management.case_repository import CaseRepository
from common.exceptions import (
    EvidenceError,
    IntegrityVerificationError,
    JsonFileError,
)
from common.json_utils import read_json_object, write_json
from common.time_utils import utc_now_iso
from evidence.hash_calculator import HashCalculator
from evidence.manifest_builder import ManifestBuilder
from models.evidence_item import EvidenceItem
from models.evidence_manifest import EvidenceManifest

_HASH_LINE_PATTERN = re.compile(r"^([0-9a-fA-F]{64})  (.+)$")
VERIFICATION_FILENAME = "integrity_verification.json"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    case_id: str
    verified_at: str
    item_count: int
    matched_count: int
    missing_paths: tuple[str, ...] = ()
    mismatched_paths: tuple[str, ...] = ()
    untracked_paths: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def success(self) -> bool:
        return not (
            self.missing_paths
            or self.mismatched_paths
            or self.untracked_paths
            or self.errors
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "verified_at": self.verified_at,
            "success": self.success,
            "item_count": self.item_count,
            "matched_count": self.matched_count,
            "missing_paths": list(self.missing_paths),
            "mismatched_paths": list(self.mismatched_paths),
            "untracked_paths": list(self.untracked_paths),
            "errors": list(self.errors),
        }


class IntegrityVerifier:
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

    def verify(
        self,
        *,
        raise_on_failure: bool = True,
    ) -> VerificationResult:
        """Verify evidence and retain the outcome of this check for the UI."""
        try:
            result = self._verify(raise_on_failure=False)
        except (EvidenceError, OSError) as exc:
            write_json(
                self.paths.analysis / VERIFICATION_FILENAME,
                {
                    "case_id": self.case_id,
                    "verified_at": utc_now_iso(),
                    "success": False,
                    "errors": [str(exc)],
                },
            )
            raise
        write_json(
            self.paths.analysis / VERIFICATION_FILENAME,
            result.to_dict(),
        )
        if raise_on_failure and not result.success:
            raise IntegrityVerificationError(_failure_message(result))
        return result

    def _verify(
        self,
        *,
        raise_on_failure: bool = True,
    ) -> VerificationResult:
        manifest = self._load_manifest()
        items = self._load_items(manifest)
        hash_entries = self._load_hash_entries()
        missing: list[str] = []
        mismatched: list[str] = []
        errors: list[str] = []
        matched = 0

        manifest_paths = {item.stored_path: item.sha256 for item in items}
        if len(manifest_paths) != len(items):
            raise IntegrityVerificationError("Manifest chứa stored_path trùng lặp.")
        if set(hash_entries) != set(manifest_paths):
            errors.append("hashes.sha256 không có cùng danh sách file với manifest.")
        errors.extend(self._custody_errors(items))

        for item in items:
            path = self._resolve_stored_path(item.stored_path)
            if not path.exists():
                missing.append(item.stored_path)
                continue
            if path.is_symlink() or not path.is_file():
                mismatched.append(item.stored_path)
                continue
            result = self.calculator.calculate(path)
            expected_hash = item.sha256
            listed_hash = hash_entries.get(item.stored_path)
            if (
                expected_hash is None
                or result.sha256 != expected_hash
                or result.size_bytes != item.size_bytes
                or listed_hash != expected_hash
            ):
                mismatched.append(item.stored_path)
                continue
            matched += 1

        try:
            discovered = {
                path.relative_to(self.paths.root).as_posix()
                for path in ManifestBuilder(
                    self.case_id,
                    self.repository.project,
                    calculator=self.calculator,
                ).discover_files()
            }
        except EvidenceError as exc:
            errors.append(str(exc))
            discovered = set()
        untracked = sorted(discovered - set(manifest_paths))
        verification = VerificationResult(
            case_id=self.case_id,
            verified_at=utc_now_iso(),
            item_count=len(items),
            matched_count=matched,
            missing_paths=tuple(sorted(missing)),
            mismatched_paths=tuple(sorted(mismatched)),
            untracked_paths=tuple(untracked),
            errors=tuple(errors),
        )
        if raise_on_failure and not verification.success:
            raise IntegrityVerificationError(_failure_message(verification))
        return verification

    def _load_manifest(self) -> dict[str, Any]:
        try:
            manifest = read_json_object(self.paths.manifest_json)
        except JsonFileError as exc:
            raise IntegrityVerificationError(str(exc)) from exc
        try:
            parsed = EvidenceManifest.from_dict(manifest)
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrityVerificationError(
                f"manifest.json không hợp lệ: {exc}"
            ) from exc
        if parsed.case_id != self.case_id:
            raise IntegrityVerificationError("manifest.json không khớp Case.")
        return manifest

    def _load_items(
        self,
        manifest: dict[str, Any],
    ) -> list[EvidenceItem]:
        try:
            parsed = EvidenceManifest.from_dict(manifest)
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrityVerificationError(
                f"EvidenceItem trong manifest không hợp lệ: {exc}"
            ) from exc
        return list(parsed.evidence_items)

    def _load_hash_entries(self) -> dict[str, str]:
        if not self.paths.hashes_sha256.is_file():
            raise IntegrityVerificationError(
                f"Không tìm thấy {self.paths.hashes_sha256.name}."
            )
        entries: dict[str, str] = {}
        try:
            lines = self.paths.hashes_sha256.read_text(
                encoding="utf-8-sig"
            ).splitlines()
        except OSError as exc:
            raise IntegrityVerificationError(
                f"Không thể đọc hashes.sha256: {exc}"
            ) from exc
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            match = _HASH_LINE_PATTERN.fullmatch(line)
            if not match:
                raise IntegrityVerificationError(
                    f"hashes.sha256 không hợp lệ tại dòng {line_number}."
                )
            digest = match.group(1).lower()
            stored_path = _validate_relative_path(match.group(2))
            if stored_path in entries:
                raise IntegrityVerificationError(
                    f"hashes.sha256 trùng đường dẫn: {stored_path}"
                )
            entries[stored_path] = digest
        return entries

    def _resolve_stored_path(self, value: str) -> Path:
        stored_path = _validate_relative_path(value)
        candidate = self.paths.root.joinpath(
            *PurePosixPath(stored_path).parts
        ).resolve()
        try:
            candidate.relative_to(self.paths.root)
        except ValueError as exc:
            raise IntegrityVerificationError(
                f"Evidence path nằm ngoài Case: {stored_path}"
            ) from exc
        return candidate

    def _custody_errors(
        self,
        items: list[EvidenceItem],
    ) -> list[str]:
        try:
            custody = read_json_object(self.paths.chain_of_custody_json)
        except JsonFileError as exc:
            return [str(exc)]
        if custody.get("case_id") != self.case_id:
            return ["chain_of_custody.json không khớp Case."]
        entries = custody.get("entries")
        if not isinstance(entries, list):
            return ["chain_of_custody.json thiếu entries hợp lệ."]

        registered = {
            entry.get("evidence_id"): entry
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("action") == "evidence_registered"
            and isinstance(entry.get("evidence_id"), str)
        }
        errors: list[str] = []
        for item in items:
            entry = registered.get(item.evidence_id)
            if entry is None:
                errors.append(f"Chain of custody thiếu {item.evidence_id}.")
                continue
            expected = {
                "stored_path": item.stored_path,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
                "collector_id": item.collector_id,
                "hostname": item.hostname,
            }
            if any(entry.get(key) != value for key, value in expected.items()):
                errors.append(f"Chain of custody không khớp {item.evidence_id}.")
        return errors


def _validate_relative_path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or ":" in path.parts[0]
    ):
        raise IntegrityVerificationError(f"Evidence path không an toàn: {value}")
    return path.as_posix()


def _failure_message(result: VerificationResult) -> str:
    details = []
    if result.missing_paths:
        details.append(f"missing={len(result.missing_paths)}")
    if result.mismatched_paths:
        details.append(f"mismatched={len(result.mismatched_paths)}")
    if result.untracked_paths:
        details.append(f"untracked={len(result.untracked_paths)}")
    if result.errors:
        details.append(f"errors={len(result.errors)}")
    summary = ", ".join(details) or "unknown"
    return f"Kiểm tra toàn vẹn thất bại ({summary})."
