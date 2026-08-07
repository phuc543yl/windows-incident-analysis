from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from collections.abc import Mapping
from pathlib import Path

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
)
from common.json_utils import read_json_object
from evidence.evidence_service import EvidenceService
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

    def wait_for_task(self, task_id: str) -> dict:
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
                self.assertTrue(
                    collector.output_filename.endswith(".json")
                )

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
        registry = CollectorRegistry(
            (StubLiveCollector(), StubArtifactCollector())
        )
        service = CollectionService(
            self.temp_path,
            registry=registry,
            local_client=FakeLocalClient(),
        )

        results = service.collect_case(case.case_id)
        paths = service.repository.paths(case.case_id)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.succeeded for result in results))
        self.assertEqual(results[0].record_count, 2)
        self.assertEqual(
            json.loads(paths.live.joinpath("system.json").read_text())[
                0
            ]["hostname"],
            "WIN-LAB01",
        )
        self.assertTrue(
            paths.raw_artifact_dir("event_logs")
            .joinpath("Security.evtx")
            .is_file()
        )
        collection_records = [
            json.loads(line)
            for line in paths.collection_log.read_text().splitlines()
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

    def test_local_collection_can_continue_after_collector_error(
        self,
    ) -> None:
        case, _ = self.prepare_local_case(
            live_collectors=("system", "processes"),
            artifact_collectors=(),
        )
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry(
                (StubLiveCollector(), StubFailedCollector())
            ),
            local_client=FakeLocalClient(),
            continue_on_error=True,
        )

        results = service.collect_case(case.case_id)

        self.assertEqual(
            [result.status for result in results],
            [CollectionStatus.SUCCEEDED, CollectionStatus.FAILED],
        )
        self.assertIn("collector failed", results[1].errors[0])

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

        with self.assertRaisesRegex(CollectionError, "processes thất bại"):
            service.collect_case(case.case_id)

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
            registry=CollectorRegistry(
                (StubLiveCollector(), StubArtifactCollector())
            ),
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

        results = service.collect_case(case.case_id)

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
            all(
                item["case_id"] == case.case_id
                for item in manifest["evidence_items"]
            )
        )
        self.assertTrue(
            all(result.metadata["bundle_imported"] for result in results)
        )
        self.assertEqual(
            {result.metadata["imported_evidence_count"] for result in results},
            {2},
        )
        self.assertEqual(
            EvidenceService(self.temp_path).verify_case(case.case_id)[
                "matched_count"
            ],
            2,
        )

    def test_collection_rejects_closed_case(self) -> None:
        case, _ = self.prepare_local_case()
        self.case_service.close_case(case.case_id)
        service = CollectionService(
            self.temp_path,
            registry=CollectorRegistry(
                (StubLiveCollector(), StubArtifactCollector())
            ),
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
