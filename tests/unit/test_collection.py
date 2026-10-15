from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from case_management.audit_logger import AuditLogger
from case_management.case_service import CaseService
from collection.artifacts._helpers import run_export_script
from collection.artifacts.evtx_collector import EvtxCollector
from collection.artifacts.file_collector import FileCollector
from collection.artifacts.memory_collector import MemoryCollector
from collection.artifacts.registry_collector import RegistryCollector
from collection.collection_service import CollectionService
from collection.collector_registry import (
    BaseCollector,
    CollectorOutput,
    CollectorRegistry,
    build_default_registry,
)
from collection.plan_builder import PlanBuilder
from common.constants import (
    SUPPORTED_ARTIFACT_COLLECTORS,
    SUPPORTED_LIVE_COLLECTORS,
)
from common.enums import (
    ArtifactType,
    CollectionStatus,
    EvidenceCategory,
    OperationMode,
)
from common.exceptions import (
    CaseClosedError,
    CollectionError,
    CollectorNotFoundError,
    IntegrityVerificationError,
)
from common.json_utils import read_json_object
from evidence.evidence_service import EvidenceService
from evidence.hash_calculator import HashCalculator
from models.collection_plan import CollectionPlan
from models.evidence_item import EvidenceItem, stable_evidence_id
from models.evidence_manifest import EvidenceManifest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeLocalClient:
    def __init__(self, json_value=None) -> None:
        self.json_value = json_value
        self.scripts: list[str] = []
        self.closed = False

    def execute_powershell_json(
        self,
        script: str,
        *,
        timeout_seconds=None,
    ):
        del timeout_seconds
        self.scripts.append(script)
        return self.json_value

    def copy_file(
        self,
        source: str | Path,
        destination: str | Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        source_path = Path(source).resolve()
        destination_path = Path(destination).resolve()
        if destination_path.exists() and not overwrite:
            raise FileExistsError(destination_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)
        return destination_path

    def close(self) -> None:
        self.closed = True


class FakeAgentClient:
    def __init__(self) -> None:
        self.submitted_plan: CollectionPlan | None = None
        self.download_call: dict | None = None
        self.closed = False
        self.bundle_bytes = b""
        self.bundle_sha256 = ""

    def submit_collection(self, plan: CollectionPlan) -> str:
        self.submitted_plan = plan
        system_data = b'[{"hostname":"WIN-REMOTE"}]'
        event_log_data = b"synthetic-agent-evtx"
        evidence = {
            "acquisition/live/system.json": (
                system_data,
                ArtifactType.SYSTEM,
                EvidenceCategory.LIVE,
                "system",
            ),
            "acquisition/raw/EventLogs/Security.evtx": (
                event_log_data,
                ArtifactType.EVENT_LOGS,
                EvidenceCategory.RAW_ARTIFACT,
                "event_logs",
            ),
        }
        items = []
        for path, (content, artifact_type, category, collector_id) in evidence.items():
            digest = hashlib.sha256(content).hexdigest()
            items.append(
                EvidenceItem(
                    case_id=plan.case_id,
                    evidence_id=stable_evidence_id(
                        plan.case_id,
                        path,
                        digest,
                    ),
                    artifact_type=artifact_type,
                    category=category,
                    source_path=path,
                    stored_path=path,
                    collector_id=collector_id,
                    hostname="WIN-REMOTE",
                    sha256=digest,
                    size_bytes=len(content),
                    collected_at="2026-07-29T08:00:00Z",
                    metadata={"collected_by": "AGENT-001"},
                )
            )
        manifest = EvidenceManifest(
            case_id=plan.case_id,
            generated_by="AGENT-001",
            generated_at="2026-07-29T08:00:01Z",
            evidence_items=tuple(items),
        ).to_dict()
        buffer = io.BytesIO()
        with zipfile.ZipFile(
            buffer,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for path, (content, _, _, _) in evidence.items():
                archive.writestr(path, content)
            archive.writestr(
                "acquisition/manifest.json",
                json.dumps(manifest),
            )
        self.bundle_bytes = buffer.getvalue()
        self.bundle_sha256 = hashlib.sha256(self.bundle_bytes).hexdigest()
        return "TASK/001"

    def wait_for_task(self, task_id: str, *, on_progress=None) -> dict:
        if on_progress is not None:
            on_progress("Agent: Collector 1/2: system...")
        return {
            "task_id": task_id,
            "status": "completed",
            "bundle_sha256": self.bundle_sha256,
        }

    def download_bundle(
        self,
        task_id: str,
        destination: str | Path,
        *,
        expected_sha256: str | None = None,
    ) -> Path:
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_bytes(self.bundle_bytes)
        self.download_call = {
            "task_id": task_id,
            "destination": destination_path,
            "expected_sha256": expected_sha256,
        }
        return destination_path

    def close(self) -> None:
        self.closed = True


class StubLiveCollector(BaseCollector):
    collector_id = "system"
    category = EvidenceCategory.LIVE
    output_filename = "system.json"

    def collect(
        self,
        client,
        destination: Path,
        options: Mapping,
    ) -> CollectorOutput:
        del client, destination, options
        return CollectorOutput(
            data=[{"hostname": "WIN-LAB01"}, {"hostname": "WIN-LAB02"}],
            metadata={"source": "stub"},
        )


class StubArtifactCollector(BaseCollector):
    collector_id = "event_logs"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(
        self,
        client,
        destination: Path,
        options: Mapping,
    ) -> CollectorOutput:
        del client, options
        artifact = destination / "Security.evtx"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"evtx")
        return CollectorOutput(files=(artifact,))


class StubFailedCollector(BaseCollector):
    collector_id = "processes"
    category = EvidenceCategory.LIVE
    output_filename = "processes.json"

    def collect(
        self,
        client,
        destination: Path,
        options: Mapping,
    ) -> CollectorOutput:
        del client, destination, options
        raise RuntimeError("collector failed")


class ChangingLiveCollector(StubLiveCollector):
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, client, destination, options):
        self.calls += 1
        return CollectorOutput(
            data=[{"hostname": "WIN-LAB01", "generation": self.calls}]
        )


class FreshArtifactCollector(StubArtifactCollector):
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, client, destination, options):
        self.calls += 1
        artifact = destination / "Security.evtx"
        if artifact.exists():
            raise RuntimeError("Artifact đã tồn tại")
        artifact.write_bytes(f"evtx generation {self.calls}".encode())
        return CollectorOutput(files=(artifact,))


class CollectorRegistryTests(unittest.TestCase):
    def test_default_registry_contains_every_supported_collector(self) -> None:
        registry = build_default_registry()

        self.assertEqual(
            set(registry.ids(EvidenceCategory.LIVE)),
            set(SUPPORTED_LIVE_COLLECTORS),
        )
        self.assertEqual(
            set(registry.ids("raw_artifact")),
            set(SUPPORTED_ARTIFACT_COLLECTORS),
        )

    def test_registry_rejects_duplicates_and_unknown_lookup(self) -> None:
        registry = CollectorRegistry((StubLiveCollector(),))

        with self.assertRaisesRegex(CollectionError, "đã được đăng ký"):
            registry.register(StubLiveCollector())
        with self.assertRaises(CollectorNotFoundError):
            registry.get("network")
        self.assertFalse(registry.contains("../outside"))

    def test_collector_output_counts_records_and_normalizes_paths(
        self,
    ) -> None:
        output = CollectorOutput(data={"hostname": "WIN-LAB01"})
        records = CollectorOutput(data=[1, 2, 3])

        self.assertEqual(output.record_count, 1)
        self.assertEqual(records.record_count, 3)


class LiveCollectorTests(unittest.TestCase):
    def test_live_collectors_return_expected_json_shape(self) -> None:
        registry = build_default_registry()
        for collector_id in SUPPORTED_LIVE_COLLECTORS:
            collector = registry.get(collector_id)
            value = {} if collector_id == "system" else []
            client = FakeLocalClient(value)
            with self.subTest(collector_id=collector_id):
                output = collector.collect(
                    client,
                    Path("."),
                    {},
                )
                self.assertEqual(
                    collector.category,
                    EvidenceCategory.LIVE,
                )
                self.assertEqual(output.data, value)
                self.assertIn("ConvertTo-Json", client.scripts[0])
                self.assertTrue(collector.output_filename.endswith(".json"))

    def test_live_collector_rejects_wrong_response_shape(self) -> None:
        collector = build_default_registry().get("processes")
        client = FakeLocalClient({"not": "an array"})

        with self.assertRaisesRegex(ValueError, "JSON array"):
            collector.collect(client, Path("."), {})


class ArtifactCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)

    def test_file_collector_copies_only_explicit_files(self) -> None:
        source = self.temp_path / "suspicious.ps1"
        source.write_text("Write-Host test", encoding="utf-8")
        destination = self.temp_path / "raw"
        client = FakeLocalClient()

        output = FileCollector().collect(
            client,
            destination,
            {
                "collector_options": {
                    "files": {"paths": [str(source)]},
                }
            },
        )

        self.assertEqual(output.record_count, 1)
        self.assertEqual(output.files[0].read_text(), "Write-Host test")
        self.assertTrue(source.is_file())

    def test_file_and_memory_collectors_warn_when_not_configured(
        self,
    ) -> None:
        client = FakeLocalClient()
        for collector in (FileCollector(), MemoryCollector()):
            with self.subTest(collector=collector.collector_id):
                output = collector.collect(
                    client,
                    self.temp_path / collector.collector_id,
                    {},
                )
                self.assertEqual(output.files, ())
                self.assertTrue(output.warnings)

    def test_evtx_collector_uses_configured_channels(self) -> None:
        destination = (self.temp_path / "EventLogs").resolve()
        destination.mkdir()
        artifact = destination / "Security.evtx"
        artifact.write_bytes(b"evtx")
        client = FakeLocalClient(
            {
                "files": [str(artifact)],
                "warnings": ["Optional log unavailable"],
            }
        )

        output = EvtxCollector().collect(
            client,
            destination,
            {
                "collector_options": {
                    "event_logs": {"channels": ["Security"]},
                }
            },
        )

        self.assertEqual(output.files, (artifact,))
        self.assertEqual(output.warnings, ("Optional log unavailable",))
        self.assertIn("'Security'", client.scripts[0])
        self.assertNotIn("PowerShell/Operational", client.scripts[0])

    def test_export_helper_rejects_file_outside_destination(self) -> None:
        destination = (self.temp_path / "raw").resolve()
        outside = self.temp_path / "outside.evtx"
        outside.write_bytes(b"outside")
        client = FakeLocalClient([str(outside)])

        with self.assertRaisesRegex(CollectionError, "ngoài thư mục"):
            run_export_script(client, destination, "ignored")

    def test_registry_collector_rejects_unknown_hive(self) -> None:
        with self.assertRaisesRegex(ValueError, "không hỗ trợ"):
            RegistryCollector().collect(
                FakeLocalClient(),
                self.temp_path,
                {
                    "collector_options": {
                        "registry": {"hives": ["SYSTEM", "USER_SECRET"]},
                    }
                },
            )


class PlanBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.builder = PlanBuilder(self.temp_path)

    def test_build_can_reduce_profile_collectors(self) -> None:
        plan = self.builder.build(
            case_id="CASE-20260729-001",
            profile_id="general_investigation",
            live_collectors=("system", "processes"),
            artifact_collectors=("event_logs",),
        )

        self.assertEqual(plan.live_collectors, ("system", "processes"))
        self.assertEqual(plan.artifact_collectors, ("event_logs",))

    def test_build_rejects_collector_outside_profile(self) -> None:
        with self.assertRaisesRegex(ValueError, "ngoài investigation"):
            self.builder.build(
                case_id="CASE-20260729-001",
                profile_id="account_compromise",
                artifact_collectors=("memory",),
            )

    def test_plan_override_requires_agent_id_and_clears_it_for_local(
        self,
    ) -> None:
        local_plan = self.builder.build(
            case_id="CASE-20260729-001",
            profile_id="account_compromise",
        )
        with self.assertRaisesRegex(ValueError, "target_agent_id"):
            PlanBuilder.with_overrides(local_plan, mode="agent")

        agent_plan = PlanBuilder.with_overrides(
            local_plan,
            mode="agent",
            target_agent_id="AGENT-001",
        )
        restored = PlanBuilder.with_overrides(agent_plan, mode="local")

        self.assertEqual(agent_plan.mode, OperationMode.AGENT)
        self.assertEqual(agent_plan.target_agent_id, "AGENT-001")
        self.assertEqual(restored.mode, OperationMode.LOCAL)
        self.assertIsNone(restored.target_agent_id)


class CollectionServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.case_service = CaseService(self.temp_path, actor="analyst")

    def prepare_local_case(
        self,
        *,
        live_collectors=("system",),
        artifact_collectors=("event_logs",),
    ):
        case = self.case_service.create_case(
            title="Collection test",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )
        plan = self.case_service.repository.load_collection_plan(case.case_id)
        plan.live_collectors = tuple(live_collectors)
        plan.artifact_collectors = tuple(artifact_collectors)
        plan.__post_init__()
        self.case_service.repository.save_collection_plan(case.case_id, plan)
        return case, plan

    def test_local_collection_persists_outputs_results_and_audit(
        self,
    ) -> None:
        case, _ = self.prepare_local_case()
        registry = CollectorRegistry((StubLiveCollector(), StubArtifactCollector()))
        service = CollectionService(
            self.temp_path,
            registry=registry,
            local_client=FakeLocalClient(),
        )

        messages = []
        results = service.collect_case(case.case_id, on_progress=messages.append)
        paths = service.repository.paths(case.case_id)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.succeeded for result in results))
        self.assertEqual(results[0].record_count, 2)
        self.assertEqual(
            json.loads(paths.live.joinpath("system.json").read_text())[0]["hostname"],
            "WIN-LAB01",
        )
        self.assertTrue(
            paths.raw_artifact_dir("event_logs").joinpath("Security.evtx").is_file()
        )
        self.assertTrue(
            EvidenceService(self.temp_path).verify_case(case.case_id)["success"]
        )
        collection_records = [
            json.loads(line) for line in paths.collection_log.read_text().splitlines()
        ]
        self.assertEqual(len(collection_records), 2)
        audit_actions = [
            entry["action"]
            for entry in AuditLogger(
                case.case_id,
                self.temp_path,
            ).read_entries()
        ]
        self.assertIn("collection_started", audit_actions)
        self.assertIn("collection_completed", audit_actions)
        self.assertIn("Collector 1/2: system...", messages)
        self.assertIn("Collector 2/2: event_logs...", messages)
        self.assertTrue(any("system: thành công, 2 bản ghi" in msg for msg in messages))
        self.assertIn("Thu thập hoàn tất", messages[-1])

    def test_recollection_preserves_old_bundle_and_verifies_new_live_and_evtx(
        self,
    ) -> None:
        case, _ = self.prepare_local_case()
        live = ChangingLiveCollector()
        raw = FreshArtifactCollector()
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((live, raw)),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        old_live = (paths.live / "system.json").read_bytes()
        old_raw = (paths.raw_artifact_dir("event_logs") / "Security.evtx").read_bytes()
        old_manifest = paths.manifest_json.read_bytes()

        messages = []
        results = service.collect_case(case.case_id, on_progress=messages.append)

        self.assertTrue(all(result.succeeded for result in results))
        self.assertEqual(read_json_object(paths.manifest_json)["item_count"], 2)
        self.assertEqual(
            json.loads((paths.live / "system.json").read_text())[0]["generation"], 2
        )
        self.assertEqual(
            (paths.raw_artifact_dir("event_logs") / "Security.evtx").read_bytes(),
            b"evtx generation 2",
        )
        self.assertTrue(
            EvidenceService(self.temp_path).verify_case(case.case_id)["success"]
        )
        bundles = list(paths.bundles.glob("before_collection_*.zip"))
        self.assertEqual(len(bundles), 1)
        with zipfile.ZipFile(bundles[0]) as archive:
            self.assertEqual(archive.read("acquisition/live/system.json"), old_live)
            self.assertEqual(
                archive.read("acquisition/raw/EventLogs/Security.evtx"), old_raw
            )
            self.assertEqual(archive.read("acquisition/manifest.json"), old_manifest)
        inspection = EvidenceService(self.temp_path).inspect_bundle(bundles[0])
        self.assertTrue(inspection["valid_zip"])
        self.assertTrue(any("lưu Evidence Bundle" in message for message in messages))
        self.assertTrue(any("đăng ký SHA-256" in message for message in messages))
        self.assertFalse(list(paths.bundles.glob("local-collection-*")))

    def test_recollection_refuses_existing_mismatch_without_overwrite_or_rebaseline(
        self,
    ) -> None:
        case, _ = self.prepare_local_case(artifact_collectors=())
        live = ChangingLiveCollector()
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((live,)),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        manifest = paths.manifest_json.read_bytes()
        changed = b'[{"hostname":"modified"}]'
        (paths.live / "system.json").write_bytes(changed)

        with self.assertRaises(IntegrityVerificationError):
            service.collect_case(case.case_id)

        self.assertEqual(live.calls, 1)
        self.assertEqual((paths.live / "system.json").read_bytes(), changed)
        self.assertEqual(paths.manifest_json.read_bytes(), manifest)
        self.assertFalse(list(paths.bundles.glob("before_collection_*.zip")))

    def test_snapshot_with_changed_archived_bytes_stops_before_collection(self) -> None:
        case, _ = self.prepare_local_case(artifact_collectors=())
        live = ChangingLiveCollector()
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((live,)),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        before = (paths.live / "system.json").read_bytes()
        build = EvidenceService.build_bundle

        def changed_snapshot(instance, *args, **kwargs):
            result = build(instance, *args, **kwargs)
            with zipfile.ZipFile(result.bundle_path) as archive:
                contents = {name: archive.read(name) for name in archive.namelist()}
            contents["acquisition/live/system.json"] = b"changed snapshot bytes"
            with zipfile.ZipFile(
                result.bundle_path, "w", zipfile.ZIP_DEFLATED
            ) as archive:
                for name, data in contents.items():
                    archive.writestr(name, data)
            return replace(
                result, sha256=HashCalculator().calculate(result.bundle_path).sha256
            )

        with patch(
            "collection.evidence_update.EvidenceService.build_bundle", changed_snapshot
        ):
            with self.assertRaisesRegex(IntegrityVerificationError, "trong snapshot"):
                service.collect_case(case.case_id)
        self.assertEqual(live.calls, 1)
        self.assertEqual((paths.live / "system.json").read_bytes(), before)

    def test_agent_collection_does_not_rebaseline_changed_existing_evidence(
        self,
    ) -> None:
        case, _ = self.prepare_local_case(artifact_collectors=())
        local = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((ChangingLiveCollector(),)),
            local_client=FakeLocalClient(),
        )
        local.collect_case(case.case_id)
        paths = local.repository.paths(case.case_id)
        manifest = paths.manifest_json.read_bytes()
        (paths.live / "system.json").write_bytes(b"modified local evidence")
        remote = CollectionService(self.temp_path, agent_client=FakeAgentClient())

        with self.assertRaisesRegex(CollectionError, "toàn vẹn thất bại"):
            remote.collect_case(case.case_id, mode="agent", agent_id="AGENT-001")
        self.assertEqual(paths.manifest_json.read_bytes(), manifest)
        self.assertEqual(
            (paths.live / "system.json").read_bytes(), b"modified local evidence"
        )

    def test_collection_archives_unregistered_existing_files_before_replacement(
        self,
    ) -> None:
        case, _ = self.prepare_local_case(artifact_collectors=())
        paths = self.case_service.repository.paths(case.case_id)
        old = b'[{"hostname":"old acquisition"}]'
        (paths.live / "system.json").write_bytes(old)
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((ChangingLiveCollector(),)),
            local_client=FakeLocalClient(),
        )

        service.collect_case(case.case_id)

        bundles = list(paths.bundles.glob("before_collection_*.zip"))
        self.assertEqual(len(bundles), 1)
        with zipfile.ZipFile(bundles[0]) as archive:
            self.assertEqual(archive.read("acquisition/live/system.json"), old)
        self.assertTrue(
            EvidenceService(self.temp_path).verify_case(case.case_id)["success"]
        )

    def test_recollection_registers_successful_outputs_when_later_collector_stops(
        self,
    ) -> None:
        case, plan = self.prepare_local_case(artifact_collectors=())
        live = ChangingLiveCollector()
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((live, StubFailedCollector())),
            local_client=FakeLocalClient(),
            continue_on_error=False,
        )
        service.collect_case(case.case_id)
        plan.live_collectors = ("system", "processes")
        self.case_service.repository.save_collection_plan(case.case_id, plan)

        with self.assertRaisesRegex(CollectionError, "processes thất bại"):
            service.collect_case(case.case_id)

        paths = service.repository.paths(case.case_id)
        self.assertEqual(
            json.loads((paths.live / "system.json").read_text())[0]["generation"], 2
        )
        self.assertTrue(
            EvidenceService(self.temp_path).verify_case(case.case_id)["success"]
        )
        self.assertEqual(len(list(paths.bundles.glob("before_collection_*.zip"))), 1)
        self.assertFalse(list(paths.bundles.glob("local-collection-*")))

    def test_failed_artifact_export_leaves_previous_raw_file_unchanged(self) -> None:
        case, _ = self.prepare_local_case(live_collectors=())
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((FreshArtifactCollector(),)),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        manifest = paths.manifest_json.read_bytes()

        class IncompleteExport(StubArtifactCollector):
            def collect(self, client, destination, options):
                (destination / "Security.evtx").write_bytes(b"incomplete")
                raise RuntimeError("export interrupted")

        service.registry = CollectorRegistry((IncompleteExport(),))
        results = service.collect_case(case.case_id)

        self.assertEqual(results[0].status, CollectionStatus.FAILED)
        self.assertEqual(
            (paths.raw_artifact_dir("event_logs") / "Security.evtx").read_bytes(),
            b"evtx generation 1",
        )
        self.assertEqual(paths.manifest_json.read_bytes(), manifest)
        self.assertTrue(
            EvidenceService(self.temp_path).verify_case(case.case_id)["success"]
        )

    def test_unrelated_evidence_change_during_collection_is_not_rebaselined(
        self,
    ) -> None:
        case, plan = self.prepare_local_case()
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry(
                (ChangingLiveCollector(), FreshArtifactCollector())
            ),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        original_manifest = paths.manifest_json.read_bytes()

        class ConcurrentChange(ChangingLiveCollector):
            def collect(self, client, destination, options):
                (paths.raw_artifact_dir("event_logs") / "Security.evtx").write_bytes(
                    b"changed elsewhere"
                )
                return super().collect(client, destination, options)

        plan.artifact_collectors = ()
        self.case_service.repository.save_collection_plan(case.case_id, plan)
        service.registry = CollectorRegistry((ConcurrentChange(),))
        with self.assertRaisesRegex(IntegrityVerificationError, "ngoài output"):
            service.collect_case(case.case_id)

        self.assertEqual(paths.manifest_json.read_bytes(), original_manifest)
        self.assertFalse(list(paths.bundles.glob("local-collection-*")))
        snapshot = next(paths.bundles.glob("before_collection_*.zip"))
        self.assertTrue(
            EvidenceService(self.temp_path).inspect_bundle(snapshot)["valid_zip"]
        )

    def test_installed_output_changed_again_is_not_rebaselined(self) -> None:
        case, plan = self.prepare_local_case(artifact_collectors=())
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((ChangingLiveCollector(),)),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        original_manifest = paths.manifest_json.read_bytes()

        class ChangeInstalledOutput(StubFailedCollector):
            def collect(self, client, destination, options):
                (paths.live / "system.json").write_bytes(b"changed after installation")
                return CollectorOutput(data=[])

        plan.live_collectors = ("system", "processes")
        self.case_service.repository.save_collection_plan(case.case_id, plan)
        service.registry = CollectorRegistry(
            (ChangingLiveCollector(), ChangeInstalledOutput())
        )
        with self.assertRaisesRegex(
            IntegrityVerificationError, "Output thu thập đã đổi"
        ):
            service.collect_case(case.case_id)
        self.assertEqual(paths.manifest_json.read_bytes(), original_manifest)

    def test_metadata_change_during_collection_is_not_rebaselined(self) -> None:
        case, _ = self.prepare_local_case(artifact_collectors=())
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((ChangingLiveCollector(),)),
            local_client=FakeLocalClient(),
        )
        service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)
        original_manifest = paths.manifest_json.read_bytes()

        class ChangeMetadata(ChangingLiveCollector):
            def collect(self, client, destination, options):
                paths.hashes_sha256.write_text("changed metadata", encoding="utf-8")
                return super().collect(client, destination, options)

        service.registry = CollectorRegistry((ChangeMetadata(),))
        with self.assertRaisesRegex(IntegrityVerificationError, "Metadata bằng chứng"):
            service.collect_case(case.case_id)
        self.assertEqual(paths.manifest_json.read_bytes(), original_manifest)

    def test_local_collection_can_continue_after_collector_error(
        self,
    ) -> None:
        case, _ = self.prepare_local_case(
            live_collectors=("system", "processes"),
            artifact_collectors=(),
        )
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((StubLiveCollector(), StubFailedCollector())),
            local_client=FakeLocalClient(),
            continue_on_error=True,
        )

        messages = []
        results = service.collect_case(case.case_id, on_progress=messages.append)

        self.assertEqual(
            [result.status for result in results],
            [CollectionStatus.SUCCEEDED, CollectionStatus.FAILED],
        )
        self.assertIn("collector failed", results[1].errors[0])
        self.assertTrue(any("processes: thất bại" in msg for msg in messages))
        self.assertTrue(any("Lỗi: collector failed" in msg for msg in messages))
        self.assertIn("1 thất bại", messages[-1])

    def test_progress_keeps_partial_collector_warnings(self) -> None:
        case, _ = self.prepare_local_case(artifact_collectors=())

        class WarningCollector(StubLiveCollector):
            def collect(self, client, destination, options):
                return CollectorOutput(data=[], warnings=("Thiếu quyền đọc một mục",))

        messages = []
        result = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((WarningCollector(),)),
            local_client=FakeLocalClient(),
        ).collect_case(case.case_id, on_progress=messages.append)

        self.assertEqual(result[0].status, CollectionStatus.PARTIAL)
        self.assertTrue(any("hoàn tất có cảnh báo" in msg for msg in messages))
        self.assertTrue(any("Thiếu quyền đọc một mục" in msg for msg in messages))

    def test_local_collection_can_stop_on_first_error(self) -> None:
        case, _ = self.prepare_local_case(
            live_collectors=("processes",),
            artifact_collectors=(),
        )
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((StubFailedCollector(),)),
            local_client=FakeLocalClient(),
            continue_on_error=False,
        )

        messages = []
        with self.assertRaisesRegex(CollectionError, "processes thất bại"):
            service.collect_case(case.case_id, on_progress=messages.append)
        self.assertTrue(any("processes: thất bại" in msg for msg in messages))
        self.assertFalse(any("Thu thập hoàn tất" in msg for msg in messages))

    def test_missing_registered_collector_becomes_failed_result(
        self,
    ) -> None:
        case, _ = self.prepare_local_case(
            live_collectors=("system",),
            artifact_collectors=(),
        )
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry(),
            local_client=FakeLocalClient(),
            continue_on_error=True,
        )

        results = service.collect_case(case.case_id)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, CollectionStatus.FAILED)
        self.assertIn("Không tìm thấy collector", results[0].errors[0])

    def test_agent_id_cannot_be_silently_used_in_local_mode(self) -> None:
        case, _ = self.prepare_local_case()
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((StubLiveCollector(), StubArtifactCollector())),
            local_client=FakeLocalClient(),
        )

        with self.assertRaisesRegex(ValueError, "mode.*agent"):
            service.collect_case(case.case_id, agent_id="AGENT-001")

    def test_agent_collection_saves_bundle_and_returns_results(self) -> None:
        case = self.case_service.create_case(
            title="Agent collection",
            target_hostname="WIN-REMOTE",
            mode="agent",
            target_agent_id="AGENT-001",
            profile_id="account_compromise",
        )
        plan = self.case_service.repository.load_collection_plan(case.case_id)
        plan.live_collectors = ("system",)
        plan.artifact_collectors = ("event_logs",)
        self.case_service.repository.save_collection_plan(case.case_id, plan)
        agent = FakeAgentClient()
        service = CollectionService(
            self.temp_path,
            agent_client=agent,
        )

        messages = []
        results = service.collect_case(case.case_id, on_progress=messages.append)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.succeeded for result in results))
        self.assertEqual(agent.submitted_plan.case_id, case.case_id)
        self.assertEqual(
            agent.download_call["expected_sha256"],
            agent.bundle_sha256,
        )
        self.assertEqual(
            agent.download_call["destination"].name,
            "TASK_001.zip",
        )
        self.assertTrue(agent.download_call["destination"].is_file())
        paths = self.case_service.repository.paths(case.case_id)
        self.assertTrue((paths.live / "system.json").is_file())
        self.assertTrue(
            (paths.raw_artifact_dir("event_logs") / "Security.evtx").is_file()
        )
        manifest = read_json_object(paths.manifest_json)
        self.assertEqual(manifest["case_id"], case.case_id)
        self.assertEqual(manifest["item_count"], 2)
        self.assertTrue(
            all(item["case_id"] == case.case_id for item in manifest["evidence_items"])
        )
        self.assertTrue(all(result.metadata["bundle_imported"] for result in results))
        self.assertEqual(
            {result.metadata["imported_evidence_count"] for result in results},
            {2},
        )
        self.assertEqual(
            EvidenceService(self.temp_path).verify_case(case.case_id)["matched_count"],
            2,
        )
        self.assertIn("Agent: Collector 1/2: system...", messages)
        self.assertTrue(any("tải Evidence Bundle" in msg for msg in messages))
        self.assertTrue(any("nhập bằng chứng" in msg for msg in messages))
        self.assertIn("Thu thập hoàn tất", messages[-1])

    def test_collection_rejects_closed_case(self) -> None:
        case, _ = self.prepare_local_case()
        self.case_service.close_case(case.case_id)
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry((StubLiveCollector(), StubArtifactCollector())),
            local_client=FakeLocalClient(),
        )

        with self.assertRaises(CaseClosedError):
            service.collect_case(case.case_id)

    def test_service_close_releases_both_clients(self) -> None:
        local = FakeLocalClient()
        agent = FakeAgentClient()
        service = CollectionService(
            self.temp_path,
            local_client=local,
            agent_client=agent,
        )

        service.close()

        self.assertTrue(local.closed)
        self.assertTrue(agent.closed)


if __name__ == "__main__":
    unittest.main()
