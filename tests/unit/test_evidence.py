from __future__ import annotations

import hashlib
import shutil
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_service import CaseService
from common.exceptions import (
    EvidenceError,
    IntegrityVerificationError,
)
from common.json_utils import read_json_object, write_json
from evidence.bundle_builder import BundleBuilder
from evidence.bundle_reader import BundleReader
from evidence.evidence_service import EvidenceService
from evidence.hash_calculator import HashCalculator
from evidence.integrity_verifier import IntegrityVerifier
from evidence.manifest_builder import ManifestBuilder

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class EvidenceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.case_service = CaseService(self.temp_path, actor="analyst")
        self.case = self.case_service.create_case(
            title="Evidence test",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )
        self.paths = self.case_service.repository.paths(self.case.case_id)

    def add_evidence(self) -> tuple[Path, Path]:
        live_file = self.paths.live / "system.json"
        raw_file = self.paths.raw_artifact_dir("event_logs") / "Security.evtx"
        write_json(
            live_file,
            {"hostname": "WIN-LAB01", "os_name": "Windows 11"},
        )
        raw_file.write_bytes(b"EVTX test evidence")
        return live_file, raw_file

    def build_manifest(self):
        self.add_evidence()
        return ManifestBuilder(
            self.case.case_id,
            self.temp_path,
        ).build(collected_by="analyst")


class HashCalculatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)

    def test_calculate_streams_sha256_and_size(self) -> None:
        evidence = self.temp_path / "evidence.bin"
        evidence.write_bytes(b"forensic evidence")

        result = HashCalculator(chunk_size=4).calculate(evidence)

        self.assertEqual(
            result.sha256,
            hashlib.sha256(b"forensic evidence").hexdigest(),
        )
        self.assertEqual(result.size_bytes, len(b"forensic evidence"))
        self.assertEqual(result.path, evidence.resolve())

    def test_calculate_rejects_missing_file_and_invalid_chunk(self) -> None:
        with self.assertRaises(ValueError):
            HashCalculator(chunk_size=0)
        with self.assertRaisesRegex(EvidenceError, "Không tìm thấy"):
            HashCalculator().calculate(self.temp_path / "missing.bin")

    def test_calculate_rejects_symbolic_link(self) -> None:
        source = self.temp_path / "source.bin"
        link = self.temp_path / "link.bin"
        source.write_bytes(b"evidence")
        try:
            link.symlink_to(source)
        except OSError as exc:
            self.skipTest(f"Không thể tạo symlink: {exc}")

        with self.assertRaisesRegex(EvidenceError, "symbolic link"):
            HashCalculator().calculate(link)


class ManifestBuilderTests(EvidenceTestCase):
    def test_build_creates_manifest_hash_list_and_custody(self) -> None:
        live_file, raw_file = self.add_evidence()

        manifest = ManifestBuilder(
            self.case.case_id,
            self.temp_path,
        ).build(collected_by="analyst")

        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["hash_algorithm"], "sha256")
        self.assertEqual(manifest["item_count"], 2)
        items = {item["stored_path"]: item for item in manifest["evidence_items"]}
        live_path = live_file.relative_to(self.paths.root).as_posix()
        raw_path = raw_file.relative_to(self.paths.root).as_posix()
        self.assertEqual(items[live_path]["category"], "live")
        self.assertEqual(items[live_path]["artifact_type"], "system")
        self.assertEqual(
            items[raw_path]["category"],
            "raw_artifact",
        )
        self.assertEqual(
            items[raw_path]["artifact_type"],
            "event_logs",
        )
        self.assertEqual(items[raw_path]["hostname"], "WIN-LAB01")
        self.assertEqual(
            items[raw_path]["sha256"],
            hashlib.sha256(raw_file.read_bytes()).hexdigest(),
        )

        hash_lines = self.paths.hashes_sha256.read_text().splitlines()
        self.assertEqual(len(hash_lines), 2)
        self.assertTrue(all("  acquisition/" in line for line in hash_lines))
        custody = read_json_object(self.paths.chain_of_custody_json)
        self.assertEqual(len(custody["entries"]), 2)
        self.assertTrue(
            all(
                entry["action"] == "evidence_registered" for entry in custody["entries"]
            )
        )

    def test_build_uses_source_map_and_stable_evidence_ids(self) -> None:
        _, raw_file = self.add_evidence()
        stored_path = raw_file.relative_to(self.paths.root).as_posix()
        builder = ManifestBuilder(self.case.case_id, self.temp_path)

        first = builder.build(
            collected_by="analyst",
            source_map={stored_path: r"C:\Windows\Security.evtx"},
        )
        second = builder.build(
            collected_by="analyst",
            source_map={stored_path: r"C:\Windows\Security.evtx"},
        )

        first_ids = {item["evidence_id"] for item in first["evidence_items"]}
        second_ids = {item["evidence_id"] for item in second["evidence_items"]}
        self.assertEqual(first_ids, second_ids)
        raw_item = next(
            item
            for item in second["evidence_items"]
            if item["stored_path"] == stored_path
        )
        self.assertEqual(
            raw_item["source_path"],
            "C:/Windows/Security.evtx",
        )
        self.assertFalse(raw_item["metadata"]["source_path_inferred"])
        custody = read_json_object(self.paths.chain_of_custody_json)
        self.assertEqual(len(custody["entries"]), 2)

    def test_build_rejects_empty_case(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "chưa có evidence"):
            ManifestBuilder(
                self.case.case_id,
                self.temp_path,
            ).build(collected_by="analyst")

    def test_build_rejects_unsafe_source_map_key(self) -> None:
        self.add_evidence()
        with self.assertRaisesRegex(ValueError, "source_map"):
            ManifestBuilder(
                self.case.case_id,
                self.temp_path,
            ).build(
                collected_by="analyst",
                source_map={"../outside": "outside"},
            )

    def test_discovery_rejects_symbolic_link(self) -> None:
        outside = self.temp_path / "outside.evtx"
        outside.write_bytes(b"outside")
        link = self.paths.raw_artifact_dir("event_logs") / "linked.evtx"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"Không thể tạo symlink: {exc}")

        with self.assertRaisesRegex(EvidenceError, "symbolic link"):
            ManifestBuilder(
                self.case.case_id,
                self.temp_path,
            ).discover_files()


class IntegrityVerifierTests(EvidenceTestCase):
    def test_verify_succeeds_for_unchanged_evidence(self) -> None:
        manifest = self.build_manifest()

        result = IntegrityVerifier(
            self.case.case_id,
            self.temp_path,
        ).verify()

        self.assertTrue(result.success)
        self.assertEqual(result.item_count, manifest["item_count"])
        self.assertEqual(result.matched_count, manifest["item_count"])

    def test_verify_detects_modified_file(self) -> None:
        self.build_manifest()
        raw_file = self.paths.raw_artifact_dir("event_logs") / "Security.evtx"
        raw_file.write_bytes(b"tampered")
        verifier = IntegrityVerifier(self.case.case_id, self.temp_path)

        result = verifier.verify(raise_on_failure=False)

        self.assertFalse(result.success)
        self.assertIn(
            raw_file.relative_to(self.paths.root).as_posix(),
            result.mismatched_paths,
        )
        with self.assertRaises(IntegrityVerificationError):
            verifier.verify()

    def test_verify_detects_missing_and_untracked_files(self) -> None:
        self.build_manifest()
        raw_file = self.paths.raw_artifact_dir("event_logs") / "Security.evtx"
        raw_file.unlink()
        untracked = self.paths.live / "users.json"
        write_json(untracked, [{"name": "analyst"}])

        result = IntegrityVerifier(
            self.case.case_id,
            self.temp_path,
        ).verify(raise_on_failure=False)

        self.assertEqual(len(result.missing_paths), 1)
        self.assertEqual(
            result.untracked_paths,
            ("acquisition/live/users.json",),
        )

    def test_verify_detects_hash_list_inconsistency(self) -> None:
        self.build_manifest()
        self.paths.hashes_sha256.write_text(
            f"{'0' * 64}  acquisition/live/system.json\n",
            encoding="utf-8",
        )

        result = IntegrityVerifier(
            self.case.case_id,
            self.temp_path,
        ).verify(raise_on_failure=False)

        self.assertFalse(result.success)
        self.assertTrue(result.errors)
        self.assertTrue(result.mismatched_paths)

    def test_verify_detects_chain_of_custody_inconsistency(self) -> None:
        self.build_manifest()
        custody = read_json_object(self.paths.chain_of_custody_json)
        custody["entries"][0]["sha256"] = "0" * 64
        write_json(self.paths.chain_of_custody_json, custody)

        result = IntegrityVerifier(
            self.case.case_id,
            self.temp_path,
        ).verify(raise_on_failure=False)

        self.assertFalse(result.success)
        self.assertTrue(any("Chain of custody" in error for error in result.errors))

    def test_verify_rejects_manifest_path_traversal(self) -> None:
        manifest = self.build_manifest()
        manifest["evidence_items"][0]["stored_path"] = "../outside"
        write_json(self.paths.manifest_json, manifest)

        with self.assertRaisesRegex(
            IntegrityVerificationError,
            "không an toàn",
        ):
            IntegrityVerifier(
                self.case.case_id,
                self.temp_path,
            ).verify()


class BundleTests(EvidenceTestCase):
    def test_build_bundle_contains_only_case_evidence_metadata_and_logs(
        self,
    ) -> None:
        self.build_manifest()
        (self.paths.analysis / "not_evidence.txt").write_text("exclude")
        (self.paths.logs / "collection.log").write_text("audit")

        result = BundleBuilder(
            self.case.case_id,
            self.temp_path,
        ).build()
        reader = BundleReader(result.bundle_path)
        files = set(reader.list_files())

        self.assertTrue(result.bundle_path.is_file())
        self.assertTrue(result.bundle_path.with_suffix(".zip.sha256").is_file())
        self.assertIn("case.json", files)
        self.assertIn("target.json", files)
        self.assertIn("collection_plan.json", files)
        self.assertIn("acquisition/manifest.json", files)
        self.assertIn("logs/collection.log", files)
        self.assertNotIn("analysis/not_evidence.txt", files)
        self.assertFalse(any(name.startswith("bundles/") for name in files))
        self.assertEqual(
            reader.read_manifest()["case_id"],
            self.case.case_id,
        )
        verification = reader.verify(expected_sha256=result.sha256)
        self.assertTrue(verification["valid_zip"])

    def test_bundle_refuses_tampered_evidence(self) -> None:
        self.build_manifest()
        (self.paths.live / "system.json").write_text(
            '{"tampered": true}',
            encoding="utf-8",
        )

        with self.assertRaises(IntegrityVerificationError):
            BundleBuilder(
                self.case.case_id,
                self.temp_path,
            ).build()

    def test_bundle_rejects_unsafe_output_name_and_overwrite(self) -> None:
        self.build_manifest()
        builder = BundleBuilder(self.case.case_id, self.temp_path)

        with self.assertRaises(ValueError):
            builder.build(output_name="../outside.zip")
        builder.build(output_name="case.zip")
        with self.assertRaises(FileExistsError):
            builder.build(output_name="case.zip")

    def test_reader_rejects_path_traversal(self) -> None:
        archive_path = self.temp_path / "unsafe.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../outside.txt", "unsafe")

        with self.assertRaisesRegex(EvidenceError, "không an toàn"):
            BundleReader(archive_path).list_files()

    def test_reader_rejects_symbolic_link_entry(self) -> None:
        archive_path = self.temp_path / "symlink.zip"
        info = zipfile.ZipInfo("linked")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr(info, "target")

        with self.assertRaisesRegex(EvidenceError, "symbolic link"):
            BundleReader(archive_path).list_files()

    def test_reader_extracts_safely_and_refuses_existing_file(self) -> None:
        self.build_manifest()
        bundle = BundleBuilder(
            self.case.case_id,
            self.temp_path,
        ).build()
        destination = self.temp_path / "extracted"
        reader = BundleReader(bundle.bundle_path)

        result = reader.extract(destination)

        self.assertEqual(result, destination.resolve())
        self.assertTrue((destination / "acquisition" / "manifest.json").is_file())
        with self.assertRaises(FileExistsError):
            reader.extract(destination)

    def test_reader_detects_bundle_hash_mismatch(self) -> None:
        self.build_manifest()
        bundle = BundleBuilder(
            self.case.case_id,
            self.temp_path,
        ).build()

        with self.assertRaises(IntegrityVerificationError):
            BundleReader(bundle.bundle_path).verify(
                expected_sha256="0" * 64,
            )


class EvidenceServiceTests(EvidenceTestCase):
    def test_ensure_preserved_verifies_existing_manifest_without_rewriting_it(
        self,
    ) -> None:
        self.add_evidence()
        service = EvidenceService(self.temp_path, actor="examiner")
        manifest = service.ensure_preserved(self.case.case_id)
        before = self.paths.manifest_json.read_bytes()

        again = service.ensure_preserved(self.case.case_id)

        self.assertEqual(again, manifest)
        self.assertEqual(self.paths.manifest_json.read_bytes(), before)

    def test_ensure_preserved_refuses_changed_evidence_without_rebaseline(self) -> None:
        self.add_evidence()
        service = EvidenceService(self.temp_path, actor="examiner")
        service.ensure_preserved(self.case.case_id)
        before = self.paths.manifest_json.read_bytes()
        (self.paths.live / "system.json").write_bytes(b"modified")

        with self.assertRaises(IntegrityVerificationError):
            service.ensure_preserved(self.case.case_id)
        self.assertEqual(self.paths.manifest_json.read_bytes(), before)

    def test_preserve_and_verify_case_are_audited(self) -> None:
        self.add_evidence()
        service = EvidenceService(self.temp_path, actor="examiner")

        manifest = service.preserve_case(self.case.case_id)
        verification = service.verify_case(self.case.case_id)

        self.assertEqual(manifest["item_count"], 2)
        self.assertTrue(verification["success"])
        actions = [
            entry["action"]
            for entry in AuditLogger(
                self.case.case_id,
                self.temp_path,
            ).read_entries()
        ]
        self.assertIn("evidence_preserved", actions)
        self.assertIn("evidence_verified", actions)

    def test_preserve_refuses_silent_manifest_rebaseline(self) -> None:
        self.add_evidence()
        service = EvidenceService(self.temp_path, actor="examiner")
        service.preserve_case(self.case.case_id)

        with self.assertRaisesRegex(EvidenceError, "Manifest đã tồn tại"):
            service.preserve_case(self.case.case_id)

    def test_build_bundle_automatically_creates_missing_manifest(
        self,
    ) -> None:
        self.add_evidence()
        service = EvidenceService(self.temp_path, actor="examiner")

        bundle = service.build_bundle(self.case.case_id)

        self.assertTrue(self.paths.manifest_json.is_file())
        self.assertTrue(bundle.bundle_path.is_file())
        inspection = service.inspect_bundle(
            bundle.bundle_path,
            expected_sha256=bundle.sha256,
        )
        self.assertEqual(
            inspection["manifest"]["case_id"],
            self.case.case_id,
        )

    def test_closed_case_can_be_verified_after_preservation(self) -> None:
        self.add_evidence()
        service = EvidenceService(self.temp_path, actor="examiner")
        service.preserve_case(self.case.case_id)
        self.case_service.close_case(self.case.case_id)

        result = service.verify_case(self.case.case_id)

        self.assertTrue(result["success"])

    def test_closed_case_without_manifest_cannot_build_bundle(self) -> None:
        self.add_evidence()
        self.case_service.close_case(self.case.case_id)

        with self.assertRaisesRegex(EvidenceError, "chưa có manifest"):
            EvidenceService(
                self.temp_path,
                actor="examiner",
            ).build_bundle(self.case.case_id)


if __name__ == "__main__":
    unittest.main()
