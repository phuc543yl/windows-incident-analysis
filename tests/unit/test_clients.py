from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from clients.agent_client import AgentClient
from clients.base_client import BaseClient, CommandResult
from clients.local_client import LocalClient
from common.enums import OperationMode
from common.exceptions import (
    ClientConnectionError,
    ClientError,
    CommandExecutionError,
    ConfigurationError,
    IntegrityVerificationError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        payload=None,
        text: str = "",
        headers: dict[str, str] | None = None,
        chunks: tuple[bytes, ...] = (),
        json_error: bool = False,
    ) -> None:
        self.status_code = status_code
        self.payload = payload
        self.text = text
        self.headers = headers or {}
        self.chunks = chunks
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise ValueError("invalid json")
        return self.payload

    def iter_content(self, chunk_size: int):
        del chunk_size
        yield from self.chunks


class FakeSession:
    def __init__(
        self,
        *,
        request_responses: tuple[FakeResponse, ...] = (),
        download_responses: tuple[FakeResponse, ...] = (),
    ) -> None:
        self.request_responses = list(request_responses)
        self.download_responses = list(download_responses)
        self.request_calls: list[dict] = []
        self.download_calls: list[dict] = []
        self.closed = False

    def request(self, method: str, url: str, **kwargs):
        self.request_calls.append(
            {"method": method, "url": url, **kwargs}
        )
        return self.request_responses.pop(0)

    def get(self, url: str, **kwargs):
        self.download_calls.append({"url": url, **kwargs})
        return self.download_responses.pop(0)

    def close(self) -> None:
        self.closed = True


class BaseClientTests(unittest.TestCase):
    def test_base_client_is_abstract(self) -> None:
        with self.assertRaises(TypeError):
            BaseClient()

    def test_timeout_validation_rejects_invalid_values(self) -> None:
        for value in (True, "120", 0, -1):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    LocalClient(
                        powershell_executable="powershell.exe",
                        timeout_seconds=value,
                    )

    def test_command_result_serializes_timing_and_status(self) -> None:
        started = datetime(2026, 7, 29, 9, 0, tzinfo=timezone.utc)
        result = CommandResult(
            executable="powershell.exe",
            arguments=("-NoProfile",),
            return_code=0,
            stdout="ok",
            stderr="",
            started_at=started,
            finished_at=started + timedelta(seconds=1.25),
        )

        data = result.to_dict()

        self.assertTrue(result.success)
        self.assertEqual(result.duration_seconds, 1.25)
        self.assertEqual(data["return_code"], 0)
        self.assertEqual(data["duration_seconds"], 1.25)
        self.assertEqual(data["arguments"], ["-NoProfile"])


class LocalClientTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        self.client = LocalClient(
            powershell_executable="powershell.exe",
            timeout_seconds=30,
        )

    def test_health_check_does_not_execute_powershell(self) -> None:
        with patch(
            "clients.local_client.shutil.which",
            return_value=r"C:\Windows\System32\WindowsPowerShell"
            r"\v1.0\powershell.exe",
        ):
            status = self.client.health_check()

        self.assertEqual(status["mode"], "local")
        self.assertTrue(status["available"])
        self.assertEqual(
            status["powershell_executable"],
            "powershell.exe",
        )

    def test_execute_powershell_uses_stdin_and_never_shell(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="\ufeffĐã thu thập\n",
            stderr="",
        )
        with patch(
            "clients.local_client.subprocess.run",
            return_value=completed,
        ) as run:
            result = self.client.execute_powershell(
                "Get-Process",
                timeout_seconds=10,
            )

        command = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(command[0], "powershell.exe")
        self.assertNotIn("Get-Process", command)
        self.assertIn("Get-Process", options["input"])
        self.assertFalse(options["shell"])
        self.assertEqual(options["timeout"], 10.0)
        self.assertEqual(result.stdout, "Đã thu thập")

    def test_execute_powershell_json_returns_object_or_array(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='[{"pid": 100}, {"pid": 200}]',
            stderr="",
        )
        with patch(
            "clients.local_client.subprocess.run",
            return_value=completed,
        ):
            value = self.client.execute_powershell_json("Get-Process")

        self.assertEqual(value[1]["pid"], 200)

    def test_execute_powershell_reports_nonzero_exit(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=5,
            stdout="",
            stderr="Access is denied.",
        )
        with patch(
            "clients.local_client.subprocess.run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(
                CommandExecutionError,
                "mã 5.*Access is denied",
            ):
                self.client.execute_powershell("Get-WinEvent Security")

    def test_execute_powershell_reports_timeout(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["powershell.exe"],
            timeout=2,
        )
        with patch(
            "clients.local_client.subprocess.run",
            side_effect=timeout,
        ):
            with self.assertRaisesRegex(
                CommandExecutionError,
                "timeout 2 giây",
            ):
                self.client.execute_powershell(
                    "Start-Sleep 30",
                    timeout_seconds=2,
                )

    def test_execute_powershell_reports_missing_executable(self) -> None:
        with patch(
            "clients.local_client.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            with self.assertRaises(ClientConnectionError):
                self.client.execute_powershell("Get-Date")

    def test_execute_powershell_json_rejects_invalid_content(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="not-json",
            stderr="",
        )
        with patch(
            "clients.local_client.subprocess.run",
            return_value=completed,
        ):
            with self.assertRaisesRegex(
                CommandExecutionError,
                "JSON không hợp lệ",
            ):
                self.client.execute_powershell_json("Get-Process")

    def test_copy_file_preserves_source_and_refuses_overwrite(self) -> None:
        source = self.temp_path / "source.evtx"
        destination = self.temp_path / "case" / "Security.evtx"
        source.write_bytes(b"evidence")

        copied = self.client.copy_file(source, destination)

        self.assertEqual(copied, destination.resolve())
        self.assertEqual(source.read_bytes(), b"evidence")
        self.assertEqual(destination.read_bytes(), b"evidence")
        with self.assertRaises(FileExistsError):
            self.client.copy_file(source, destination)


class AgentClientTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)

    def make_client(self, session: FakeSession) -> AgentClient:
        return AgentClient(
            "http://127.0.0.1:8765/",
            token="test-token",
            timeout_seconds=15,
            session=session,
        )

    def test_agent_url_and_header_are_validated(self) -> None:
        for url in (
            "",
            "ftp://127.0.0.1",
            "http://user:password@127.0.0.1",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    AgentClient(url)
        with self.assertRaises(ValueError):
            AgentClient(
                "http://127.0.0.1:8765",
                token_header="X-Agent-Token\r\nInjected",
            )

    def test_from_config_reads_token_only_from_environment(self) -> None:
        session = FakeSession()
        config_path = PROJECT_ROOT / "config" / "agent.json"

        with patch.dict(
            "os.environ",
            {"WINDOWS_FORENSIC_AGENT_TOKEN": "environment-token"},
        ):
            client = AgentClient.from_config(
                config_path,
                session=session,
            )

        self.assertEqual(client.base_url, "http://127.0.0.1:8765")
        self.assertEqual(client.token, "environment-token")
        self.assertEqual(client.token_header, "X-Agent-Token")

    def test_from_config_requires_authentication_environment(self) -> None:
        config_path = PROJECT_ROOT / "config" / "agent.json"

        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(
                ConfigurationError,
                "WINDOWS_FORENSIC_AGENT_TOKEN",
            ):
                AgentClient.from_config(config_path)

    def test_health_check_sends_token_header_and_timeout(self) -> None:
        session = FakeSession(
            request_responses=(
                FakeResponse(payload={"status": "ok"}),
            )
        )
        client = self.make_client(session)

        result = client.health_check()

        self.assertEqual(result, {"status": "ok"})
        call = session.request_calls[0]
        self.assertEqual(call["method"], "GET")
        self.assertTrue(call["url"].endswith("/api/v1/health"))
        self.assertEqual(call["headers"]["X-Agent-Token"], "test-token")
        self.assertEqual(call["timeout"], 15.0)

    def test_submit_collection_accepts_only_agent_plan(self) -> None:
        session = FakeSession(
            request_responses=(
                FakeResponse(payload={"task_id": "TASK-001"}),
            )
        )
        client = self.make_client(session)

        with self.assertRaisesRegex(ValueError, "Agent Mode"):
            client.submit_collection(
                {"case_id": "CASE-1", "mode": "local"}
            )
        task_id = client.submit_collection(
            {"case_id": "CASE-1", "mode": "agent"}
        )

        self.assertEqual(task_id, "TASK-001")
        payload = session.request_calls[0]["json"]
        self.assertEqual(
            payload["collection_plan"]["case_id"],
            "CASE-1",
        )

    def test_get_task_escapes_task_id_in_url(self) -> None:
        session = FakeSession(
            request_responses=(
                FakeResponse(
                    payload={"task_id": "TASK/001", "status": "running"}
                ),
            )
        )
        client = self.make_client(session)

        result = client.get_task("TASK/001")

        self.assertEqual(result["status"], "running")
        self.assertTrue(
            session.request_calls[0]["url"].endswith(
                "/api/v1/tasks/TASK%2F001"
            )
        )

    def test_wait_for_task_returns_completed_task(self) -> None:
        session = FakeSession()
        client = self.make_client(session)
        responses = [
            {"task_id": "TASK-1", "status": "running"},
            {"task_id": "TASK-1", "status": "completed"},
        ]

        with (
            patch.object(client, "get_task", side_effect=responses),
            patch("clients.agent_client.time.sleep") as sleep,
        ):
            result = client.wait_for_task(
                "TASK-1",
                poll_interval_seconds=0.1,
                max_wait_seconds=2,
            )

        self.assertEqual(result["status"], "completed")
        sleep.assert_called_once()

    def test_wait_for_task_reports_agent_failure(self) -> None:
        session = FakeSession()
        client = self.make_client(session)

        with patch.object(
            client,
            "get_task",
            return_value={"status": "failed", "error": "Collector failed"},
        ):
            with self.assertRaisesRegex(
                ClientError,
                "Collector failed",
            ):
                client.wait_for_task("TASK-1")

    def test_wait_for_task_reports_timeout(self) -> None:
        session = FakeSession()
        client = self.make_client(session)

        with (
            patch.object(
                client,
                "get_task",
                return_value={"status": "running"},
            ),
            patch(
                "clients.agent_client.time.monotonic",
                side_effect=(10.0, 12.0),
            ),
        ):
            with self.assertRaisesRegex(
                ClientConnectionError,
                "Hết thời gian",
            ):
                client.wait_for_task(
                    "TASK-1",
                    poll_interval_seconds=0.1,
                    max_wait_seconds=1,
                )

    def test_download_bundle_verifies_sha256_and_writes_atomically(
        self,
    ) -> None:
        content = b"PK\x03\x04evidence-bundle"
        expected_hash = hashlib.sha256(content).hexdigest()
        session = FakeSession(
            download_responses=(
                FakeResponse(
                    headers={"X-Content-SHA256": expected_hash},
                    chunks=(content[:4], content[4:]),
                ),
            )
        )
        client = self.make_client(session)
        destination = self.temp_path / "bundles" / "evidence.zip"

        result = client.download_bundle("TASK-1", destination)

        self.assertEqual(result, destination.resolve())
        self.assertEqual(destination.read_bytes(), content)
        self.assertFalse(
            (destination.parent / ".evidence.zip.part").exists()
        )
        self.assertTrue(
            session.download_calls[0]["url"].endswith(
                "/api/v1/tasks/TASK-1/bundle"
            )
        )

    def test_download_bundle_removes_partial_file_on_hash_mismatch(
        self,
    ) -> None:
        session = FakeSession(
            download_responses=(
                FakeResponse(chunks=(b"tampered",)),
            )
        )
        client = self.make_client(session)
        destination = self.temp_path / "evidence.zip"

        with self.assertRaises(IntegrityVerificationError):
            client.download_bundle(
                "TASK-1",
                destination,
                expected_sha256="0" * 64,
            )

        self.assertFalse(destination.exists())
        self.assertFalse(
            (destination.parent / ".evidence.zip.part").exists()
        )

    def test_http_error_redacts_token_from_exception(self) -> None:
        session = FakeSession(
            request_responses=(
                FakeResponse(
                    status_code=401,
                    text="Invalid token test-token",
                ),
            )
        )
        client = self.make_client(session)

        with self.assertRaises(ClientError) as raised:
            client.health_check()

        self.assertNotIn("test-token", str(raised.exception))
        self.assertIn("***", str(raised.exception))

    def test_invalid_agent_json_is_reported(self) -> None:
        session = FakeSession(
            request_responses=(
                FakeResponse(json_error=True),
            )
        )
        client = self.make_client(session)

        with self.assertRaisesRegex(ClientError, "JSON không hợp lệ"):
            client.health_check()

    def test_context_manager_closes_session(self) -> None:
        session = FakeSession()

        with self.make_client(session) as client:
            self.assertEqual(client.mode, OperationMode.AGENT)

        self.assertTrue(session.closed)

    def test_connection_error_is_wrapped(self) -> None:
        session = FakeSession()

        def raise_connection_error(*args, **kwargs):
            del args, kwargs
            raise OSError("connection refused")

        session.request = raise_connection_error
        client = self.make_client(session)

        with self.assertRaisesRegex(
            ClientConnectionError,
            "Không thể kết nối Agent",
        ):
            client.health_check()


if __name__ == "__main__":
    unittest.main()
