from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from clients.agent_client import AgentClient
from clients.base_client import BaseClient
from collection.collector_registry import (
    BaseCollector,
    CollectorOutput,
    CollectorRegistry,
)
from common.enums import EvidenceCategory, OperationMode
from common.json_utils import write_json
from models.collection_plan import CollectionPlan
from models.evidence_manifest import EvidenceManifest

try:
    import flask  # noqa: F401
except ModuleNotFoundError:
    FLASK_AVAILABLE = False
    create_app = None
    shutdown_app = None
else:
    FLASK_AVAILABLE = True
    from agent.app import create_app, shutdown_app

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOKEN = "integration-test-agent-token"


class SyntheticAgentClient(BaseClient):
    mode = OperationMode.LOCAL

    def health_check(self):
        return {"available": True}


class AgentSystemCollector(BaseCollector):
    collector_id = "system"
    category = EvidenceCategory.LIVE
    output_filename = "system.json"

    def collect(self, client, destination, options):
        del client, destination, options
        return CollectorOutput(
            data={
                "hostname": "WIN-LAB-AGENT",
                "os_name": "Windows Lab",
                "is_sample": True,
            }
        )


class AgentEvtxCollector(BaseCollector):
    collector_id = "event_logs"
    category = EvidenceCategory.RAW_ARTIFACT
    output_filename = None

    def collect(self, client, destination, options):
        del client, options
        output = destination / "Security.evtx"
        output.write_bytes(b"SYNTHETIC AGENT EVTX SAMPLE")
        return CollectorOutput(files=(output,))


class FlaskResponseAdapter:
    def __init__(self, response) -> None:
        self.response = response
        self.status_code = response.status_code
        self.headers = dict(response.headers)
        self._data = response.get_data()
        self.text = self._data.decode("utf-8", errors="replace")

    def json(self):
        value = self.response.get_json()
        if value is None:
            raise ValueError("response is not JSON")
        return value

    def iter_content(self, chunk_size: int):
        try:
            for offset in range(0, len(self._data), chunk_size):
                yield self._data[offset : offset + chunk_size]
        finally:
            self.response.close()


class FlaskSessionAdapter:
    def __init__(self, app) -> None:
        self.client = app.test_client()
        self.closed = False

    def request(
        self,
        method,
        url,
        *,
        headers,
        json=None,
        timeout=None,
        stream=False,
    ):
        del timeout, stream
        path = urlsplit(url).path
        response = self.client.open(
            path,
            method=method,
            headers=headers,
            json=json,
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        return FlaskResponseAdapter(response)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        self.closed = True


class BinaryResponseAdapterTests(unittest.TestCase):
    def test_binary_body_is_not_decoded_strictly_and_is_closed(self) -> None:
        response = _FakeBinaryResponse(b"PK\x03\x04\xfd\xffarchive")
        adapter = FlaskResponseAdapter(response)

        content = b"".join(adapter.iter_content(chunk_size=4))

        self.assertEqual(content, b"PK\x03\x04\xfd\xffarchive")
        self.assertIn("\ufffd", adapter.text)
        self.assertTrue(response.closed)


class _FakeBinaryResponse:
    status_code = 200
    headers = {"Content-Type": "application/zip"}

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.closed = False

    def get_data(self):
        return self.data

    def get_json(self):
        return None

    def close(self) -> None:
        self.closed = True


@unittest.skipUnless(FLASK_AVAILABLE, "Thiếu Flask trong môi trường test.")
class AgentWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.config_path = self.temp_path / "config" / "agent.json"
        config = json.loads(
            self.config_path.read_text(encoding="utf-8")
        )
        config["collector_allowlist"] = ["system", "event_logs"]
        config["buffer"]["delete_after_successful_transfer"] = False
        write_json(self.config_path, config)
        registry = CollectorRegistry(
            (AgentSystemCollector(), AgentEvtxCollector())
        )
        self.app = create_app(
            self.config_path,
            root=self.temp_path,
            environment={"WINDOWS_FORENSIC_AGENT_TOKEN": TOKEN},
            registry=registry,
            local_client=SyntheticAgentClient(),
            testing=True,
        )
        self.addCleanup(shutdown_app, self.app)
        self.session = FlaskSessionAdapter(self.app)
        self.client = AgentClient(
            "http://agent.test",
            token=TOKEN,
            session=self.session,
            timeout_seconds=5,
        )
        self.addCleanup(self.client.close)

    def plan(self) -> CollectionPlan:
        return CollectionPlan(
            case_id="CASE-20260729-001",
            profile_id="account_compromise",
            mode=OperationMode.AGENT,
            live_collectors=("system",),
            artifact_collectors=("event_logs",),
            target_agent_id="WIN-LAB-AGENT",
        )

    def test_agent_client_to_api_to_hashed_bundle(self) -> None:
        health = self.client.health_check()
        task_id = self.client.submit_collection(self.plan())
        task = self.client.wait_for_task(
            task_id,
            poll_interval_seconds=0.01,
            max_wait_seconds=5,
        )
        bundle = self.client.download_bundle(
            task_id,
            self.temp_path / "downloaded_agent_bundle.zip",
            expected_sha256=task["bundle_sha256"],
        )

        self.assertEqual(health["agent_id"], "WIN-LAB-AGENT")
        self.assertEqual(task["status"], "completed")
        self.assertTrue(bundle.is_file())
        with zipfile.ZipFile(bundle) as archive:
            names = set(archive.namelist())
            manifest = json.loads(
                archive.read("acquisition/manifest.json")
            )
        self.assertIn("acquisition/live/system.json", names)
        self.assertIn(
            "acquisition/raw/EventLogs/Security.evtx",
            names,
        )
        self.assertEqual(manifest["item_count"], 2)
        parsed_manifest = EvidenceManifest.from_dict(manifest)
        self.assertEqual(parsed_manifest.case_id, self.plan().case_id)
        self.assertTrue(
            all(
                item.sha256 is not None
                and len(item.sha256) == 64
                and item.evidence_id.startswith("EVID-")
                and bool(item.hostname)
                for item in parsed_manifest.evidence_items
            )
        )

    def test_agent_rejects_invalid_token_through_real_client_contract(self) -> None:
        bad_client = AgentClient(
            "http://agent.test",
            token="wrong-token",
            session=FlaskSessionAdapter(self.app),
            timeout_seconds=5,
        )
        self.addCleanup(bad_client.close)

        with self.assertRaisesRegex(Exception, "HTTP 401"):
            bad_client.health_check()


if __name__ == "__main__":
    unittest.main()
