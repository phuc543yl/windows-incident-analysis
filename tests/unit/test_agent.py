from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from clients.base_client import BaseClient
from collection.collector_registry import (
    BaseCollector,
    CollectorOutput,
    CollectorRegistry,
)
from common.enums import EvidenceCategory, OperationMode
from common.exceptions import AgentError, ConfigurationError
from common.json_utils import write_json
from common.time_utils import utc_now
from models.collection_plan import CollectionPlan
from models.evidence_manifest import EvidenceManifest
from agent.agent_logger import AgentLogger
from agent.authentication import AgentAuthenticator
from agent.configuration import AgentSettings
from agent.local_buffer import LocalBuffer
from agent.task_executor import TaskExecutor

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
TOKEN = "unit-test-agent-token"


class FakeLocalClient(BaseClient):
    mode = OperationMode.LOCAL

    def __init__(self) -> None:
        super().__init__(timeout_seconds=10)
        self.closed = False

    def health_check(self):
        return {"available": True}

    def close(self) -> None:
        self.closed = True


class FakeSystemCollector(BaseCollector):
    collector_id = "system"
    category = EvidenceCategory.LIVE
    output_filename = "system.json"

    def collect(self, client, destination, options):
        del client, destination, options
        return CollectorOutput(
            data={
                "hostname": "WIN-LAB01",
                "os_name": "Windows Test",
            }
        )


class FakeUsersCollector(BaseCollector):
    collector_id = "users"
    category = EvidenceCategory.LIVE
    output_filename = "users.json"

    def collect(self, client, destination, options):
        del client, destination, options
        raise RuntimeError("collector intentionally failed")


class FakeEvtxCollector(BaseCollector):
    collector_id = "event_logs"
    category = EvidenceCategory.RAW_ARTIFACT

    def collect(self, client, destination, options):
        del client, options
        path = destination / "Security.evtx"
        path.write_bytes(b"EVTX test evidence")
        return CollectorOutput(files=(path,))


class AgentTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.config_path = self.temp_path / "config" / "agent.json"
        self.registry = CollectorRegistry(
            (
                FakeSystemCollector(),
                FakeUsersCollector(),
                FakeEvtxCollector(),
            )
        )
        self.write_config(
            collector_allowlist=["system", "users", "event_logs"]
        )

    def write_config(self, **changes) -> dict:
        config = json.loads(
            (PROJECT_ROOT / "config" / "agent.json").read_text(
                encoding="utf-8"
            )
        )
        for key, value in changes.items():
            if "." not in key:
                config[key] = value
                continue
            section, field = key.split(".", maxsplit=1)
            config[section][field] = value
        self.config_path.write_text(
            json.dumps(config),
            encoding="utf-8",
        )
        return config

    def settings(self, **changes) -> AgentSettings:
        if changes:
            self.write_config(**changes)
        return AgentSettings.load(
            self.config_path,
            root=self.temp_path,
            environment={"WINDOWS_FORENSIC_AGENT_TOKEN": TOKEN},
        )

    def plan(
        self,
        *,
        live_collectors=("system",),
        artifact_collectors=("event_logs",),
        target_agent_id="WIN-LAB-AGENT",
        mode=OperationMode.AGENT,
    ) -> CollectionPlan:
        return CollectionPlan(
            case_id="CASE-20260729-001",
            profile_id="general_investigation",
            mode=mode,
            live_collectors=live_collectors,
            artifact_collectors=artifact_collectors,
            target_agent_id=target_agent_id,
        )

    def app(self):
        local_client = FakeLocalClient()
        app = create_app(
            self.config_path,
            root=self.temp_path,
            environment={"WINDOWS_FORENSIC_AGENT_TOKEN": TOKEN},
            registry=self.registry,
            local_client=local_client,
            testing=True,
        )
        self.addCleanup(shutdown_app, app)
        return app

    @property
    def headers(self) -> dict[str, str]:
        return {"X-Agent-Token": TOKEN}


class AgentSettingsTests(AgentTestCase):
    def test_loads_valid_config_and_token_from_environment(self) -> None:
        settings = self.settings()

        self.assertEqual(settings.agent_id, "WIN-LAB-AGENT")
        self.assertEqual(settings.token, TOKEN)
        self.assertEqual(settings.token_header, "X-Agent-Token")
        self.assertEqual(
            settings.buffer_directory,
            self.temp_path / "runtime" / "agent_buffer",
        )
        self.assertIn("event_logs", settings.collector_allowlist)

    def test_requires_authentication_environment_variable(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "biến môi trường"):
            AgentSettings.load(
                self.config_path,
                root=self.temp_path,
                environment={},
            )

    def test_rejects_token_in_config_and_unsafe_paths(self) -> None:
        config = self.write_config()
        config["authentication"]["token"] = "hardcoded"
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        with self.assertRaisesRegex(ConfigurationError, "không được lưu"):
            self.settings()

        self.write_config(**{"buffer.directory": "../outside"})
        with self.assertRaisesRegex(ConfigurationError, "an toàn"):
            self.settings()

    def test_plain_http_requires_lab_mode(self) -> None:
        self.write_config(**{"transport.lab_mode_only": False})

        with self.assertRaisesRegex(ConfigurationError, "lab_mode"):
            self.settings()

    def test_rejects_invalid_ip_port_and_header(self) -> None:
        cases = (
            ({"agent.port": 70000}, "port"),
            (
                {"transport.allowed_client_ips": ["not-an-ip"]},
                "IP",
            ),
            (
                {"authentication.token_header": "X-Test\r\nBad"},
                "token_header",
            ),
        )
        for changes, message in cases:
            with self.subTest(changes=changes):
                self.write_config(**changes)
                with self.assertRaisesRegex(
                    ConfigurationError,
                    message,
                ):
                    self.settings()


class AuthenticationAndLoggingTests(AgentTestCase):
    def test_authenticator_checks_ip_and_token(self) -> None:
        authenticator = AgentAuthenticator(self.settings())

        self.assertEqual(
            authenticator.authorize(
                remote_addr="127.0.0.1",
                supplied_token=TOKEN,
            ),
            (True, 200, ""),
        )
        self.assertEqual(
            authenticator.authorize(
                remote_addr="127.0.0.1",
                supplied_token="wrong",
            )[1],
            401,
        )
        self.assertEqual(
            authenticator.authorize(
                remote_addr="192.0.2.10",
                supplied_token=TOKEN,
            )[1],
            403,
        )

    def test_disabled_authentication_still_checks_client_ip(self) -> None:
        self.write_config(**{"authentication.enabled": False})
        settings = AgentSettings.load(
            self.config_path,
            root=self.temp_path,
            environment={},
        )
        authenticator = AgentAuthenticator(settings)

        self.assertTrue(
            authenticator.authorize(
                remote_addr="127.0.0.1",
                supplied_token=None,
            )[0]
        )
        self.assertEqual(
            authenticator.authorize(
                remote_addr="192.0.2.1",
                supplied_token=None,
            )[1],
            403,
        )

    def test_agent_logger_redacts_nested_secrets(self) -> None:
        path = self.temp_path / "runtime" / "logs" / "agent.log"
        logger = AgentLogger(path)

        logger.log(
            "test",
            details={
                "token": TOKEN,
                "nested": {
                    "password": "secret",
                    "value": "visible",
                },
            },
        )
        line = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(line["details"]["token"], "***")
        self.assertEqual(
            line["details"]["nested"]["password"],
            "***",
        )
        self.assertEqual(
            line["details"]["nested"]["value"],
            "visible",
        )
        self.assertNotIn(TOKEN, path.read_text(encoding="utf-8"))


class LocalBufferTests(AgentTestCase):
    def test_task_state_is_persisted_and_transitions_are_validated(self) -> None:
        buffer = LocalBuffer(
            self.temp_path / "buffer",
            delete_after_successful_transfer=False,
        )
        task = buffer.create(self.plan().to_dict())

        self.assertEqual(buffer.get(task.task_id).status, "queued")
        running = buffer.mark_running(task.task_id)
        self.assertEqual(running.status, "running")
        bundle = buffer.task_directory(task.task_id) / "bundle.zip"
        bundle.write_bytes(b"bundle")
        completed = buffer.mark_completed(
            task.task_id,
            collection_results=(),
            bundle_path=bundle,
            bundle_sha256=hashlib.sha256(b"bundle").hexdigest(),
            bundle_size_bytes=6,
        )

        self.assertEqual(completed.status, "completed")
        self.assertTrue(completed.bundle_available)
        self.assertEqual(len(buffer.list()), 1)
        with self.assertRaisesRegex(AgentError, "không thể chuyển"):
            buffer.mark_running(task.task_id)

    def test_transfer_can_delete_only_bundle_and_preserve_task(self) -> None:
        buffer = LocalBuffer(
            self.temp_path / "buffer",
            delete_after_successful_transfer=True,
        )
        task = buffer.create(self.plan().to_dict())
        buffer.mark_running(task.task_id)
        bundle = buffer.task_directory(task.task_id) / "bundle.zip"
        bundle.write_bytes(b"bundle")
        buffer.mark_completed(
            task.task_id,
            collection_results=(),
            bundle_path=bundle,
            bundle_sha256=hashlib.sha256(b"bundle").hexdigest(),
            bundle_size_bytes=6,
        )

        transferred = buffer.mark_transferred(task.task_id)

        self.assertFalse(bundle.exists())
        self.assertFalse(transferred.bundle_available)
        self.assertEqual(transferred.status, "completed")
        self.assertTrue(buffer.task_file(task.task_id).is_file())

    def test_rejects_invalid_task_id_and_bundle_outside_buffer(self) -> None:
        buffer = LocalBuffer(self.temp_path / "buffer")
        with self.assertRaisesRegex(AgentError, "task_id"):
            buffer.get("../outside")

        task = buffer.create(self.plan().to_dict())
        buffer.mark_running(task.task_id)
        outside = self.temp_path / "outside.zip"
        outside.write_bytes(b"outside")
        with self.assertRaisesRegex(AgentError, "ngoài"):
            buffer.mark_completed(
                task.task_id,
                collection_results=(),
                bundle_path=outside,
                bundle_sha256="0" * 64,
                bundle_size_bytes=7,
            )

    def test_cleanup_removes_only_expired_failed_tasks(self) -> None:
        buffer = LocalBuffer(
            self.temp_path / "buffer",
            retention_hours_on_failure=1,
        )
        expired = buffer.create(self.plan().to_dict())
        recent = buffer.create(self.plan().to_dict())
        buffer.mark_failed(expired.task_id, "old")
        buffer.mark_failed(recent.task_id, "new")
        old_task = buffer.get(expired.task_id)
        old_task.finished_at = utc_now() - timedelta(hours=2)
        write_json(
            buffer.task_file(expired.task_id),
            old_task.to_dict(),
        )

        removed = buffer.cleanup_failed(now=utc_now())

        self.assertEqual(removed, (expired.task_id,))
        self.assertFalse(
            buffer.task_directory(expired.task_id).exists()
        )
        self.assertTrue(
            buffer.task_directory(recent.task_id).exists()
        )

    def test_rejects_symbolic_link_buffer(self) -> None:
        target = self.temp_path / "real-buffer"
        target.mkdir()
        link = self.temp_path / "buffer-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Không thể tạo symlink: {exc}")

        with self.assertRaisesRegex(AgentError, "symbolic link"):
            LocalBuffer(link)


class TaskExecutorTests(AgentTestCase):
    def executor(self, settings: AgentSettings | None = None):
        selected_settings = settings or self.settings()
        buffer = LocalBuffer(
            selected_settings.buffer_directory,
            delete_after_successful_transfer=False,
        )
        logger = AgentLogger(selected_settings.audit_file)
        client = FakeLocalClient()
        executor = TaskExecutor(
            selected_settings,
            buffer,
            logger,
            registry=self.registry,
            local_client=client,
        )
        self.addCleanup(executor.close)
        return executor, buffer, client

    def test_executes_collectors_and_builds_hashed_bundle(self) -> None:
        executor, buffer, _ = self.executor()

        task = executor.submit(self.plan(), background=False)
        task, bundle = buffer.bundle_for(task.task_id)

        self.assertEqual(task.status, "completed")
        self.assertEqual(len(task.collection_results), 2)
        self.assertTrue(
            all(
                result["status"] == "succeeded"
                for result in task.collection_results
            )
        )
        self.assertEqual(
            hashlib.sha256(bundle.read_bytes()).hexdigest(),
            task.bundle_sha256,
        )
        with zipfile.ZipFile(bundle) as archive:
            names = set(archive.namelist())
            manifest_data = json.loads(
                archive.read("acquisition/manifest.json")
            )
            collection_data = json.loads(
                archive.read("collection_results.json")
            )
            self.assertIn(
                "acquisition/live/system.json",
                names,
            )
            self.assertIn(
                "acquisition/raw/EventLogs/Security.evtx",
                names,
            )
            self.assertIn("acquisition/manifest.json", names)
            self.assertIn("acquisition/hashes.sha256", names)
            self.assertIn("collection_results.json", names)
        manifest = EvidenceManifest.from_dict(manifest_data)
        self.assertEqual(manifest.case_id, self.plan().case_id)
        self.assertEqual(manifest.item_count, 2)
        self.assertTrue(
            all(item.evidence_id.startswith("EVID-") for item in manifest.evidence_items)
        )
        self.assertTrue(
            all(item.hostname for item in manifest.evidence_items)
        )
        self.assertTrue(
            all(
                result["evidence_item_ids"]
                for result in collection_data["collection_results"]
            )
        )

    def test_collector_failure_is_returned_without_losing_bundle(self) -> None:
        executor, buffer, _ = self.executor()
        plan = self.plan(
            live_collectors=("system", "users"),
            artifact_collectors=(),
        )

        task = executor.submit(plan, background=False)

        self.assertEqual(task.status, "completed")
        statuses = {
            result["collector_id"]: result["status"]
            for result in task.collection_results
        }
        self.assertEqual(statuses["system"], "succeeded")
        self.assertEqual(statuses["users"], "failed")
        self.assertTrue(buffer.bundle_for(task.task_id)[1].is_file())

    def test_rejects_local_wrong_agent_and_blocked_collector(self) -> None:
        executor, _, _ = self.executor()
        cases = (
            (
                self.plan(mode=OperationMode.LOCAL),
                "Agent Mode",
            ),
            (
                self.plan(target_agent_id="OTHER-AGENT"),
                "Agent này",
            ),
        )
        for plan, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(AgentError, message):
                    executor.submit(plan, background=False)

        settings = replace(
            self.settings(),
            collector_allowlist=("system",),
        )
        restricted, _, _ = self.executor(settings)
        with self.assertRaisesRegex(AgentError, "allowlist"):
            restricted.submit(self.plan(), background=False)

    def test_bundle_size_limit_marks_task_failed(self) -> None:
        settings = replace(
            self.settings(),
            max_bundle_size_bytes=1,
        )
        executor, _, _ = self.executor(settings)

        task = executor.submit(self.plan(), background=False)

        self.assertEqual(task.status, "failed")
        self.assertIn("kích thước", task.error)

    def test_rejects_submission_when_concurrency_limit_is_reached(
        self,
    ) -> None:
        executor, buffer, _ = self.executor()
        buffer.create(self.plan().to_dict())

        with self.assertRaisesRegex(AgentError, "giới hạn task"):
            executor.submit(self.plan(), background=False)

    def test_background_task_can_be_waited_and_client_is_closed(self) -> None:
        executor, _, client = self.executor()

        submitted = executor.submit(self.plan(), background=True)
        completed = executor.wait(submitted.task_id, timeout=5)
        executor.close()

        self.assertEqual(completed.status, "completed")
        self.assertTrue(client.closed)


@unittest.skipUnless(FLASK_AVAILABLE, "Thiếu Flask trong môi trường test.")
class AgentApiTests(AgentTestCase):
    def test_health_requires_token_and_allowed_ip(self) -> None:
        app = self.app()
        client = app.test_client()

        missing = client.get("/api/v1/health")
        wrong = client.get(
            "/api/v1/health",
            headers={"X-Agent-Token": "wrong"},
        )
        forbidden = client.get(
            "/api/v1/health",
            headers=self.headers,
            environ_base={"REMOTE_ADDR": "192.0.2.10"},
        )
        success = client.get(
            "/api/v1/health",
            headers=self.headers,
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(success.status_code, 200)
        self.assertEqual(
            success.get_json()["agent_id"],
            "WIN-LAB-AGENT",
        )

    def test_submit_get_and_download_bundle_matches_client_contract(
        self,
    ) -> None:
        app = self.app()
        client = app.test_client()

        submitted = client.post(
            "/api/v1/tasks",
            headers=self.headers,
            json={"collection_plan": self.plan().to_dict()},
        )

        self.assertEqual(submitted.status_code, 202)
        task_id = submitted.get_json()["task_id"]
        executor = app.extensions["agent_executor"]
        completed = executor.wait(task_id, timeout=5)
        task_response = client.get(
            f"/api/v1/tasks/{task_id}",
            headers=self.headers,
        )
        bundle_response = client.get(
            f"/api/v1/tasks/{task_id}/bundle",
            headers=self.headers,
            buffered=True,
        )

        self.assertEqual(completed.status, "completed")
        self.assertEqual(task_response.status_code, 200)
        self.assertEqual(
            task_response.get_json()["status"],
            "completed",
        )
        self.assertEqual(bundle_response.status_code, 200)
        self.assertEqual(
            bundle_response.headers["X-Content-SHA256"],
            hashlib.sha256(bundle_response.data).hexdigest(),
        )
        self.assertTrue(bundle_response.data.startswith(b"PK"))
        bundle_response.close()

    def test_api_rejects_invalid_payload_unknown_task_and_unready_bundle(
        self,
    ) -> None:
        app = self.app()
        client = app.test_client()

        invalid_json = client.post(
            "/api/v1/tasks",
            headers=self.headers,
            data="not-json",
            content_type="application/json",
        )
        invalid_plan = client.post(
            "/api/v1/tasks",
            headers=self.headers,
            json={"collection_plan": {"mode": "agent"}},
        )
        missing = client.get(
            "/api/v1/tasks/TASK-" + "0" * 32,
            headers=self.headers,
        )
        queued = app.extensions["agent_buffer"].create(
            self.plan().to_dict()
        )
        unready = client.get(
            f"/api/v1/tasks/{queued.task_id}/bundle",
            headers=self.headers,
        )

        self.assertEqual(invalid_json.status_code, 400)
        self.assertEqual(invalid_plan.status_code, 400)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(unready.status_code, 409)

    def test_api_returns_json_for_unknown_endpoint_and_method(self) -> None:
        app = self.app()
        client = app.test_client()

        missing = client.get("/api/v1/missing")
        method = client.put(
            "/api/v1/health",
            headers=self.headers,
        )

        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.get_json()["error"], "Không tìm thấy endpoint.")
        self.assertEqual(method.status_code, 405)


if __name__ == "__main__":
    unittest.main()
