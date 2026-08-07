"""Streaming SHA-256 calculation for evidence files."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from common.exceptions import EvidenceError


@dataclass(frozen=True, slots=True)
class HashResult:
    path: Path
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            "path": self.path.as_posix(),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


class HashCalculator:
    def __init__(self, *, chunk_size: int = 1024 * 1024) -> None:
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
            raise TypeError("chunk_size phải là số nguyên.")
        if chunk_size <= 0:
            raise ValueError("chunk_size phải lớn hơn 0.")
        self.chunk_size = chunk_size

    def calculate(self, path: str | Path) -> HashResult:
        evidence_path = Path(path).expanduser().resolve()
        if Path(path).expanduser().is_symlink():
            raise EvidenceError(
                f"Không hash symbolic link: {path}"
            )
        if not evidence_path.is_file():
            raise EvidenceError(
                f"Không tìm thấy evidence file: {evidence_path}"
            )

        try:
            before = evidence_path.stat()
            digest = hashlib.sha256()
            size_bytes = 0
            with evidence_path.open("rb") as handle:
                while True:
                    chunk = handle.read(self.chunk_size)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size_bytes += len(chunk)
            after = evidence_path.stat()
        except OSError as exc:
            raise EvidenceError(
                f"Không thể đọc evidence file {evidence_path}: {exc}"
            ) from exc

        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or size_bytes != after.st_size
        ):
            raise EvidenceError(
                f"Evidence thay đổi trong khi tính hash: {evidence_path}"
            )
        return HashResult(
            path=evidence_path,
            sha256=digest.hexdigest(),
            size_bytes=size_bytes,
        )

    def calculate_many(
        self,
        paths: list[str | Path] | tuple[str | Path, ...],
    ) -> tuple[HashResult, ...]:
        return tuple(self.calculate(path) for path in paths)
