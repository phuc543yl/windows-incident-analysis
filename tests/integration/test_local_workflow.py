from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from case_management.case_service import CaseService
from clients.base_client import BaseClient
from collection.collection_service import CollectionService
from collection.collector_registry import (
    BaseCollector,
    CollectorOutput,
    CollectorRegistry,
)
from common.enums import EvidenceCategory, OperationMode
from evidence.evidence_service import EvidenceService

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_EVIDENCE = PROJECT_ROOT / "tests" / "sample_evidence"


class SyntheticLocalClient(BaseClient):
    mode = OperationMode.LOCAL

    def __init__(self) -> None:
        super().__init__(timeout_seconds=5)
        self.closed = False

    def health_check(self):
        return {"available": True, "mode": self.mode.value}

    def close(self) -> None:
        self.closed = True


class SyntheticLiveCollector(BaseCollector):
    category = EvidenceCategory.LIVE

    def __init__(self, collector_id: str) -> None:
        self.collector_id = collector_id
        self.output_filename = f"{collector_id}.json"

    def collect(self, client, destination, options):
        del client, destination, options
        if self.collector_id == "system":
            return CollectorOutput(
                data=json.loads(
                    (
                        SAMPLE_EVIDENCE / "live" / "system.json"
                    ).read_text(encoding="utf-8")
                )
            )
        return CollectorOutput(
            data=[
                {
                    "collector_id": self.collector_id,
                    "hostname": "WIN-LAB01",
                    "is_sample": True,
                }
            ]
        )


class SyntheticArtifactCollector(BaseCollector):
    category = EvidenceCategory.RAW_ARTIFACT
    output_filename = None

    def __init__(self, collector_id: str) -> None:
        self.collector_id = collector_id

    def collect(self, client, destination, options):
        del client, options
        if self.collector_id == "event_logs":
            source = (
                SAMPLE_EVIDENCE
                / "raw"
                / "EventLogs"
                / "Security.evtx.sample"
            )
            output = destination / "Security.evtx"
        else:
            source = (
                SAMPLE_EVIDENCE
                / "raw"
                / "FirewallLogs"
                / "pfirewall.log"
            )
            output = destination / "pfirewall.log"
        shutil.copyfile(source, output)
        return CollectorOutput(files=(output,))


class LocalWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.case = CaseService(
            self.temp_path,
            actor="integration-test",
        ).create_case(
            title="Synthetic Local workflow",
            target_hostname="WIN-LAB01",
            profile_id="account_compromise",
        )
        collectors = tuple(
            SyntheticLiveCollector(collector_id)
            for collector_id in (
                "system",
                "users",
                "processes",
                "network",
            )
        ) + tuple(
            SyntheticArtifactCollector(collector_id)
            for collector_id in ("event_logs", "firewall_logs")
        )
        self.client = SyntheticLocalClient()
        self.collection = CollectionService(
            self.temp_path,
            registry=CollectorRegistry(collectors),
            local_client=self.client,
        )
        self.evidence = EvidenceService(
            self.temp_path,
            actor="integration-test",
        )
        self.paths = self.collection.repository.paths(self.case.case_id)

    def tearDown(self) -> None:
        self.collection.close()

    def test_collect_preserve_verify_and_bundle(self) -> None:
        results = self.collection.collect_case(self.case.case_id)

        self.assertEqual(len(results), 6)
        self.assertTrue(all(result.succeeded for result in results))
        self.assertTrue((self.paths.live / "system.json").is_file())
        self.assertTrue(
            (
                self.paths.raw_artifact_dir("event_logs")
                / "Security.evtx"
            ).is_file()
        )

        manifest = self.evidence.preserve_case(self.case.case_id)
        verification = self.evidence.verify_case(self.case.case_id)
        bundle = self.evidence.build_bundle(
            self.case.case_id,
            output_name="synthetic_evidence_bundle.zip",
        )

        self.assertEqual(manifest["item_count"], 6)
        self.assertTrue(verification["success"])
        self.assertTrue(bundle.bundle_path.is_file())
        self.assertEqual(len(bundle.sha256), 64)
        with zipfile.ZipFile(bundle.bundle_path) as archive:
            names = set(archive.namelist())
        self.assertIn("acquisition/manifest.json", names)
        self.assertIn("acquisition/raw/EventLogs/Security.evtx", names)
        self.assertIn("logs/collection.log", names)

    def test_workflow_keeps_every_output_inside_case(self) -> None:
        self.collection.collect_case(self.case.case_id)
        manifest = self.evidence.preserve_case(self.case.case_id)

        for item in manifest["evidence_items"]:
            resolved = (
                self.paths.root / item["stored_path"]
            ).resolve()
            resolved.relative_to(self.paths.root)
            self.assertTrue(resolved.is_file())
        self.assertTrue(
            all(
                item["metadata"]["source_path_inferred"]
                for item in manifest["evidence_items"]
            )
        )

    def test_closing_collection_releases_client(self) -> None:
        self.collection.close()

        self.assertTrue(self.client.closed)


if __name__ == "__main__":
    unittest.main()
