"""Safely inspect and extract Evidence Bundle ZIP files."""

from __future__ import annotations

import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from common.exceptions import EvidenceError, IntegrityVerificationError
from evidence.hash_calculator import HashCalculator


class BundleReader:
    def __init__(
        self,
        bundle_path: str | Path,
        *,
        max_member_size_bytes: int = 2 * 1024 * 1024 * 1024,
        max_total_size_bytes: int = 10 * 1024 * 1024 * 1024,
        max_compression_ratio: float = 1000.0,
    ) -> None:
        self.bundle_path = Path(bundle_path).expanduser().resolve()
        if not self.bundle_path.is_file():
            raise EvidenceError(
                f"Không tìm thấy Evidence Bundle: {self.bundle_path}"
            )
        if max_member_size_bytes <= 0 or max_total_size_bytes <= 0:
            raise ValueError("Giới hạn kích thước bundle phải lớn hơn 0.")
        if max_compression_ratio <= 0:
            raise ValueError("max_compression_ratio phải lớn hơn 0.")
        self.max_member_size_bytes = int(max_member_size_bytes)
        self.max_total_size_bytes = int(max_total_size_bytes)
        self.max_compression_ratio = float(max_compression_ratio)

    def list_files(self) -> tuple[str, ...]:
        with self._open() as archive:
            members = self._validate_members(archive)
            return tuple(
                member.filename
                for member in members
                if not member.is_dir()
            )

    def verify(
        self,
        *,
        expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        hash_result = HashCalculator().calculate(self.bundle_path)
        if expected_sha256 is not None:
            normalized = expected_sha256.strip().lower()
            if (
                len(normalized) != 64
                or any(character not in "0123456789abcdef" for character in normalized)
            ):
                raise ValueError("expected_sha256 không hợp lệ.")
            if hash_result.sha256 != normalized:
                raise IntegrityVerificationError(
                    "SHA-256 của Evidence Bundle không khớp."
                )
        files = self.list_files()
        return {
            "bundle_path": self.bundle_path.as_posix(),
            "sha256": hash_result.sha256,
            "size_bytes": hash_result.size_bytes,
            "file_count": len(files),
            "valid_zip": True,
        }

    def read_manifest(self) -> dict[str, Any]:
        manifest_name = "acquisition/manifest.json"
        with self._open() as archive:
            members = self._validate_members(archive)
            member_names = {
                member.filename
                for member in members
                if not member.is_dir()
            }
            if manifest_name not in member_names:
                raise EvidenceError(
                    "Evidence Bundle thiếu acquisition/manifest.json."
                )
            info = archive.getinfo(manifest_name)
            if info.file_size > 10 * 1024 * 1024:
                raise EvidenceError("manifest.json trong bundle quá lớn.")
            try:
                value = json.loads(
                    archive.read(info).decode("utf-8-sig")
                )
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise EvidenceError(
                    "manifest.json trong bundle không hợp lệ."
                ) from exc
            if not isinstance(value, dict):
                raise EvidenceError(
                    "manifest.json trong bundle phải là object."
                )
            return value

    def extract(
        self,
        destination: str | Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        destination_root = Path(destination).expanduser().resolve()
        with self._open() as archive:
            members = self._validate_members(archive)
            targets = [
                (
                    member,
                    destination_root.joinpath(
                        *PurePosixPath(member.filename).parts
                    ),
                )
                for member in members
                if not member.is_dir()
            ]
            if not overwrite:
                existing = [
                    target
                    for _, target in targets
                    if target.exists()
                ]
                if existing:
                    raise FileExistsError(
                        f"File giải nén đã tồn tại: {existing[0]}"
                    )
            destination_root.mkdir(parents=True, exist_ok=True)
            for member, target in targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_name(f".{target.name}.part")
                temporary.unlink(missing_ok=True)
                try:
                    with (
                        archive.open(member, "r") as source,
                        temporary.open("wb") as output,
                    ):
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
                    os.replace(temporary, target)
                except Exception:
                    temporary.unlink(missing_ok=True)
                    raise
        return destination_root

    def _open(self) -> zipfile.ZipFile:
        try:
            return zipfile.ZipFile(self.bundle_path, mode="r")
        except (OSError, zipfile.BadZipFile) as exc:
            raise EvidenceError(
                f"Evidence Bundle không phải ZIP hợp lệ: {exc}"
            ) from exc

    def _validate_members(
        self,
        archive: zipfile.ZipFile,
    ) -> tuple[zipfile.ZipInfo, ...]:
        members = tuple(archive.infolist())
        seen: set[str] = set()
        total_size = 0
        for member in members:
            name = member.filename
            path = PurePosixPath(name)
            if (
                not name
                or "\\" in name
                or path.is_absolute()
                or ".." in path.parts
                or (path.parts and ":" in path.parts[0])
            ):
                raise EvidenceError(
                    f"Bundle chứa đường dẫn không an toàn: {name}"
                )
            normalized = path.as_posix().casefold()
            if normalized in seen:
                raise EvidenceError(
                    f"Bundle chứa entry trùng lặp: {name}"
                )
            seen.add(normalized)
            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise EvidenceError(
                    f"Bundle chứa symbolic link: {name}"
                )
            if member.flag_bits & 0x1:
                raise EvidenceError(
                    f"Bundle chứa file được mã hóa: {name}"
                )
            if member.file_size > self.max_member_size_bytes:
                raise EvidenceError(
                    f"Bundle member vượt giới hạn kích thước: {name}"
                )
            total_size += member.file_size
            if total_size > self.max_total_size_bytes:
                raise EvidenceError(
                    "Tổng kích thước giải nén vượt giới hạn."
                )
            compressed = max(member.compress_size, 1)
            if member.file_size / compressed > self.max_compression_ratio:
                raise EvidenceError(
                    f"Tỷ lệ nén bất thường trong bundle: {name}"
                )
        try:
            bad_member = archive.testzip()
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise EvidenceError(
                f"Không thể kiểm tra CRC của bundle: {exc}"
            ) from exc
        if bad_member is not None:
            raise EvidenceError(
                f"Bundle có CRC không hợp lệ: {bad_member}"
            )
        return members
