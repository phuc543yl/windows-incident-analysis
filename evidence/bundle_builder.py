"""Build a verified Evidence Bundle as an atomic ZIP archive."""

from __future__ import annotations

import os
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.exceptions import EvidenceError
from common.time_utils import utc_now_iso
from evidence.hash_calculator import HashCalculator
from evidence.integrity_verifier import IntegrityVerifier


@dataclass(frozen=True, slots=True)
class BundleResult:
    case_id: str
    bundle_path: Path
    sha256: str
    size_bytes: int
    file_count: int
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "bundle_path": self.bundle_path.as_posix(),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "created_at": self.created_at,
        }


class BundleBuilder:
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

    def build(
        self,
        *,
        output_name: str = "evidence_bundle.zip",
        include_logs: bool = True,
        overwrite: bool = False,
    ) -> BundleResult:
        output_name = _validate_output_name(output_name)
        IntegrityVerifier(
            self.case_id,
            self.repository.project,
            calculator=self.calculator,
        ).verify()
        output_path = (self.paths.bundles / output_name).resolve()
        sidecar = output_path.with_suffix(f"{output_path.suffix}.sha256")
        if (
            (output_path.exists() or sidecar.exists())
            and not overwrite
        ):
            raise FileExistsError(
                f"Evidence Bundle đã tồn tại: {output_path}"
            )

        files = self._bundle_files(include_logs=include_logs)
        temporary_path = output_path.with_name(
            f".{output_path.name}.part"
        )
        temporary_path.unlink(missing_ok=True)
        try:
            with zipfile.ZipFile(
                temporary_path,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
                allowZip64=True,
            ) as archive:
                for path in files:
                    archive.write(
                        path,
                        arcname=path.relative_to(
                            self.paths.root
                        ).as_posix(),
                    )
            os.replace(temporary_path, output_path)
        except (OSError, zipfile.BadZipFile) as exc:
            temporary_path.unlink(missing_ok=True)
            raise EvidenceError(
                f"Không thể tạo Evidence Bundle: {exc}"
            ) from exc
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

        hash_result = self.calculator.calculate(output_path)
        _atomic_write_text(
            sidecar,
            f"{hash_result.sha256}  {output_path.name}\n",
        )
        return BundleResult(
            case_id=self.case_id,
            bundle_path=output_path,
            sha256=hash_result.sha256,
            size_bytes=hash_result.size_bytes,
            file_count=len(files),
            created_at=utc_now_iso(),
        )

    def _bundle_files(self, *, include_logs: bool) -> tuple[Path, ...]:
        required = (
            self.paths.case_json,
            self.paths.target_json,
            self.paths.collection_plan_json,
            self.paths.manifest_json,
            self.paths.hashes_sha256,
            self.paths.chain_of_custody_json,
        )
        for path in required:
            if not path.is_file():
                raise EvidenceError(
                    f"Thiếu file bắt buộc để tạo bundle: {path.name}"
                )

        files = list(required[:3])
        files.extend(
            path
            for path in self.paths.acquisition.rglob("*")
            if path.is_file()
        )
        if include_logs:
            files.extend(
                path
                for path in self.paths.logs.rglob("*")
                if path.is_file()
            )

        unique: dict[str, Path] = {}
        for path in files:
            if path.is_symlink():
                raise EvidenceError(
                    f"Bundle không chấp nhận symbolic link: {path}"
                )
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(self.paths.root)
            except ValueError as exc:
                raise EvidenceError(
                    f"Bundle source nằm ngoài Case: {path}"
                ) from exc
            unique[relative.as_posix()] = resolved
        return tuple(
            unique[key]
            for key in sorted(unique, key=str.casefold)
        )


def _validate_output_name(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("output_name không được để trống.")
    normalized = value.strip()
    if (
        "/" in normalized
        or "\\" in normalized
        or Path(normalized).name != normalized
        or not normalized.lower().endswith(".zip")
    ):
        raise ValueError("output_name phải là tên file .zip an toàn.")
    return normalized


def _atomic_write_text(path: Path, content: str) -> None:
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
