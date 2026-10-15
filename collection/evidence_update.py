"""Preserve a verified acquisition before installing a new local collection."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from collection.collector_registry import BaseCollector, CollectorOutput
from common.enums import EvidenceCategory
from common.exceptions import CollectionError, IntegrityVerificationError
from common.json_utils import read_json_object, write_json
from common.time_utils import filename_timestamp
from evidence.bundle_reader import BundleReader
from evidence.evidence_service import EvidenceService
from evidence.hash_calculator import HashCalculator
from evidence.integrity_verifier import IntegrityVerifier
from evidence.manifest_builder import ManifestBuilder
from models import new_id


class LocalEvidenceUpdate:
    def __init__(
        self,
        case_id: str,
        root: Path,
        *,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.repository = CaseRepository(root)
        self.paths = self.repository.paths(case_id)
        self.evidence = EvidenceService(root, actor="collection-service")
        self.calculator = HashCalculator()
        self.report = on_progress or (lambda _message: None)
        self.audit = AuditLogger(case_id, root)
        self.registered = False
        self.previous_bundle: str | None = None
        self.source_map: dict[str, str] = {}
        self.metadata_hashes: dict[Path, str] = {}
        self.installed: dict[str, tuple[str, int]] = {}
        self._temporary: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> LocalEvidenceUpdate:
        self.repository.require_open(self.paths.case_id)
        self.report("Đang kiểm tra bằng chứng trước khi thu thập...")
        if not self.paths.manifest_json.exists() and (
            self.paths.hashes_sha256.exists()
            or self.paths.chain_of_custody_json.exists()
        ):
            raise IntegrityVerificationError(
                "Thiếu manifest nhưng Case vẫn có metadata bằng chứng. "
                "Hãy khôi phục metadata gốc hoặc tạo Case mới."
            )
        existing = ManifestBuilder(
            self.paths.case_id, self.repository.project
        ).discover_files()
        if self.paths.manifest_json.exists() or existing:
            self.evidence.ensure_preserved(self.paths.case_id)
            self.registered = True
            manifest = read_json_object(self.paths.manifest_json)
            self.source_map = {
                item["stored_path"]: item["source_path"]
                for item in manifest["evidence_items"]
            }
            for path in (
                self.paths.manifest_json,
                self.paths.hashes_sha256,
                self.paths.chain_of_custody_json,
            ):
                self.metadata_hashes[path] = self.calculator.calculate(path).sha256
            self.report("Đang lưu Evidence Bundle của lần thu thập trước...")
            run_id = f"{filename_timestamp()}_{new_id('COLL').split('-', 1)[1][:12]}"
            bundle = self.evidence.build_bundle(
                self.paths.case_id,
                output_name=f"before_collection_{run_id}.zip",
            )
            BundleReader(bundle.bundle_path).verify(expected_sha256=bundle.sha256)
            self._verify_snapshot(bundle.bundle_path, manifest)
            self.previous_bundle = bundle.bundle_path.relative_to(
                self.paths.root
            ).as_posix()
            self.audit.log(
                "collection_snapshot_preserved",
                actor="collection-service",
                details={"bundle_path": self.previous_bundle, "sha256": bundle.sha256},
            )
        self._temporary = tempfile.TemporaryDirectory(
            prefix="local-collection-", dir=self.paths.bundles
        )
        return self

    def _verify_snapshot(self, bundle: Path, manifest: dict) -> None:
        """Check archived bytes against the manifest before replacing any input."""
        with zipfile.ZipFile(bundle) as archive:
            for path, expected in self.metadata_hashes.items():
                name = path.relative_to(self.paths.root).as_posix()
                if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                    raise IntegrityVerificationError(
                        f"Metadata snapshot không khớp: {name}"
                    )
            for item in manifest["evidence_items"]:
                digest = hashlib.sha256()
                size = 0
                with archive.open(item["stored_path"]) as source:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                if digest.hexdigest() != item["sha256"] or size != item["size_bytes"]:
                    raise IntegrityVerificationError(
                        f"Bằng chứng trong snapshot không khớp: {item['stored_path']}"
                    )

    def destination(self, collector: BaseCollector) -> Path:
        if self._temporary is None:
            raise RuntimeError("Collection staging chưa được khởi tạo.")
        destination = Path(self._temporary.name) / collector.collector_id
        destination.mkdir(parents=True, exist_ok=True)
        return destination

    def install(self, collector: BaseCollector, output: CollectorOutput) -> list[str]:
        staging = self.destination(collector)
        if collector.category is EvidenceCategory.LIVE:
            name = collector.output_filename or f"{collector.collector_id}.json"
            if Path(name).name != name:
                raise CollectionError("Tên file live không hợp lệ.")
            sources = (write_json(staging / name, output.data),)
            destination = self.paths.live
        else:
            sources = output.files
            destination = self.paths.raw_artifact_dir(collector.collector_id)
        output_paths: list[str] = []
        for source in sources:
            if source.is_symlink() or not source.is_file():
                raise CollectionError("Collector trả về file không hợp lệ.")
            try:
                relative = source.resolve().relative_to(staging.resolve())
            except ValueError as exc:
                raise CollectionError(
                    f"Collector {collector.collector_id} trả về file ngoài staging."
                ) from exc
            target = destination / relative
            if target.is_symlink():
                raise CollectionError("Không được ghi đè symbolic link.")
            try:
                target.resolve().relative_to(self.paths.root)
            except ValueError as exc:
                raise CollectionError("Collection output nằm ngoài Case.") from exc
            digest = self.calculator.calculate(source)
            stored_path = target.relative_to(self.paths.root).as_posix()
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(
                prefix=".collection-", dir=target.parent
            )
            os.close(descriptor)
            temporary = Path(name)
            try:
                shutil.copy2(source, temporary)
                copied = self.calculator.calculate(temporary)
                if (copied.sha256, copied.size_bytes) != (
                    digest.sha256,
                    digest.size_bytes,
                ):
                    raise CollectionError(
                        f"Bản sao bằng chứng không khớp: {stored_path}"
                    )
                os.replace(temporary, target)
                self.installed[stored_path] = (digest.sha256, digest.size_bytes)
            finally:
                temporary.unlink(missing_ok=True)
            output_paths.append(stored_path)
        return output_paths

    def _finish(self) -> None:
        if self.registered:
            for path, expected in self.metadata_hashes.items():
                if self.calculator.calculate(path).sha256 != expected:
                    raise IntegrityVerificationError(
                        "Metadata bằng chứng đã đổi trong khi thu thập; không cập nhật manifest."
                    )
            result = IntegrityVerifier(
                self.paths.case_id, self.repository.project
            ).verify(raise_on_failure=False)
            unexpected = (
                set(result.mismatched_paths) | set(result.untracked_paths)
            ) - set(self.installed)
            if result.missing_paths or result.errors or unexpected:
                raise IntegrityVerificationError(
                    "Bằng chứng ngoài output thu thập đã đổi; không cập nhật manifest. "
                    "Hãy xem integrity_verification.json và Evidence Bundle trước thu thập."
                )
        for stored_path, expected in self.installed.items():
            actual = self.calculator.calculate(self.paths.root / stored_path)
            if (actual.sha256, actual.size_bytes) != expected:
                raise IntegrityVerificationError(
                    f"Output thu thập đã đổi trước khi đăng ký: {stored_path}"
                )
        if not self.installed:
            return
        self.report("Đang đăng ký SHA-256 của dữ liệu vừa thu thập...")
        self.evidence.preserve_case(
            self.paths.case_id,
            source_map=self.source_map,
            rebuild=self.registered,
        )
        self.evidence.verify_case(self.paths.case_id)
        self.audit.log(
            "collection_evidence_updated",
            actor="collection-service",
            details={
                "output_paths": sorted(self.installed),
                "previous_bundle": self.previous_bundle,
            },
        )

    def __exit__(self, exc_type, exc, traceback) -> bool:
        try:
            # Successful collectors may have installed files before another
            # collector failed. Register only those known, checked outputs.
            self._finish()
        except Exception as failure:
            self.audit.log(
                "collection_evidence_update_failed",
                actor="collection-service",
                status="failed",
                details={
                    "reason": str(failure),
                    "previous_bundle": self.previous_bundle,
                },
            )
            raise
        finally:
            if self._temporary is not None:
                self._temporary.cleanup()
        return False
