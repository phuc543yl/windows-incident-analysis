"""High-level evidence preservation and verification service."""

from __future__ import annotations

import getpass
from pathlib import Path
from typing import Any

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.exceptions import EvidenceError, IntegrityVerificationError
from evidence.bundle_builder import BundleBuilder, BundleResult
from evidence.bundle_reader import BundleReader
from evidence.integrity_verifier import IntegrityVerifier
from evidence.manifest_builder import ManifestBuilder


class EvidenceService:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str | None = None,
    ) -> None:
        self.repository = CaseRepository(root)
        self.actor = actor.strip() if actor and actor.strip() else _default_actor()

    def preserve_case(
        self,
        case_id: str,
        *,
        source_map: dict[str, str] | None = None,
        rebuild: bool = False,
    ) -> dict[str, Any]:
        case = self.repository.require_open(case_id)
        paths = self.repository.paths(case.case_id)
        if paths.manifest_json.exists() and not rebuild:
            raise EvidenceError(
                "Manifest đã tồn tại. Hãy verify evidence hoặc truyền "
                "rebuild=True khi chủ động đăng ký lại bằng chứng."
            )
        manifest = ManifestBuilder(
            case.case_id,
            self.repository.project,
        ).build(
            collected_by=self.actor,
            source_map=source_map,
        )
        AuditLogger(case.case_id, self.repository.project).log(
            "evidence_preserved",
            actor=self.actor,
            details={
                "item_count": manifest["item_count"],
                "total_size_bytes": manifest["total_size_bytes"],
                "hash_algorithm": manifest["hash_algorithm"],
            },
        )
        return manifest

    def verify_case(self, case_id: str) -> dict[str, Any]:
        case = self.repository.load_case(case_id)
        audit = AuditLogger(case.case_id, self.repository.project)
        try:
            result = IntegrityVerifier(
                case.case_id,
                self.repository.project,
            ).verify()
        except IntegrityVerificationError as exc:
            audit.log(
                "evidence_verification_failed",
                actor=self.actor,
                status="failed",
                details={"reason": str(exc)},
            )
            raise
        audit.log(
            "evidence_verified",
            actor=self.actor,
            details={
                "item_count": result.item_count,
                "matched_count": result.matched_count,
            },
        )
        return result.to_dict()

    def build_bundle(
        self,
        case_id: str,
        *,
        output_name: str = "evidence_bundle.zip",
        include_logs: bool = True,
        overwrite: bool = False,
    ) -> BundleResult:
        case = self.repository.load_case(case_id)
        paths = self.repository.paths(case.case_id)
        if not paths.manifest_json.is_file():
            if case.status.value == "closed":
                raise EvidenceError(
                    "Case đã đóng nhưng chưa có manifest; không thể "
                    "tự động đăng ký evidence."
                )
            self.preserve_case(case.case_id)
        result = BundleBuilder(
            case.case_id,
            self.repository.project,
        ).build(
            output_name=output_name,
            include_logs=include_logs,
            overwrite=overwrite,
        )
        AuditLogger(case.case_id, self.repository.project).log(
            "evidence_bundle_created",
            actor=self.actor,
            details={
                "bundle_name": result.bundle_path.name,
                "sha256": result.sha256,
                "size_bytes": result.size_bytes,
                "file_count": result.file_count,
            },
        )
        return result

    def inspect_bundle(
        self,
        bundle_path: str | Path,
        *,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        reader = BundleReader(bundle_path)
        verification = reader.verify(expected_sha256=expected_sha256)
        verification["manifest"] = reader.read_manifest()
        return verification

    def extract_bundle(
        self,
        bundle_path: str | Path,
        destination: str | Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        return BundleReader(bundle_path).extract(
            destination,
            overwrite=overwrite,
        )


def _default_actor() -> str:
    try:
        return getpass.getuser() or "unknown"
    except Exception:
        return "unknown"
