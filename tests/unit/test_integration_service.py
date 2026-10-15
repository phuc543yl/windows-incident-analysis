from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from analysis.analysis_service import AnalysisService
from case_management.case_service import CaseService
from common.enums import ToolRunStatus
from common.exceptions import ToolIntegrationError
from common.json_utils import write_json
from integrations.integration_service import IntegrationService
from models.normalized_record import NormalizedRecord
from models.tool_result import ToolResult
from processing.processing_pipeline import ProcessingPipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeAdapter:
    def __init__(
        self,
        definition,
        runner,
        *,
        status: ToolRunStatus = ToolRunStatus.SUCCEEDED,
    ) -> None:
        self.definition = definition
        self.runner = runner
        self.tool_id = definition.tool_id
        self.artifact_type = definition.supported_artifacts[0]
        self.status = status
        self.run_inputs: tuple[Path, ...] = ()
        self.verify_integrity: bool | None = None

    def run(
        self,
        *,
        case_id,
        input_paths,
        verify_integrity=True,
    ):
        self.run_inputs = tuple(input_paths)
        self.verify_integrity = verify_integrity
        timestamp = datetime.now(timezone.utc)
        return ToolResult(
            case_id=case_id,
            tool_id=self.tool_id,
            status=self.status,
            started_at=timestamp,
            finished_at=timestamp,
            exit_code=0 if self.status is ToolRunStatus.SUCCEEDED else 1,
            error_message=(
                "" if self.status is ToolRunStatus.SUCCEEDED else "tool failed"
            ),
        )

    def parse(self, result, *, hostname=""):
        return (
            NormalizedRecord(
                case_id=result.case_id,
                source_type=f"{self.tool_id}_test",
                artifact_type=self.artifact_type,
                timestamp="2026-07-29T08:00:00Z",
                summary=f"Output from {self.tool_id}",
                hostname=hostname,
                raw_reference=(f"analysis/tool_outputs/{self.tool_id}/output.csv"),
            ),
        )


class IntegrationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(PROJECT_ROOT / "config", self.temp_path / "config")
        self.case = CaseService(
            self.temp_path,
            actor="test",
        ).create_case(
            title="Integration orchestration",
            target_hostname="WIN-LAB01",
            profile_id="account_compromise",
        )
        self.paths = CaseService(self.temp_path).repository.paths(self.case.case_id)
        self.adapters: dict[str, FakeAdapter] = {}

    def factory(self, definition, runner):
        adapter = FakeAdapter(definition, runner)
        self.adapters[definition.tool_id] = adapter
        return adapter

    def seed_event_log(self) -> Path:
        path = self.paths.raw_artifact_dir("event_logs") / "Security.evtx"
        path.write_bytes(b"synthetic evtx")
        return path

    def seed_live_process(self) -> Path:
        path = self.paths.live / "processes.json"
        write_json(
            path,
            [
                {
                    "name": "powershell.exe",
                    "pid": 4242,
                    "parent_pid": 1000,
                    "executable_path": (
                        r"C:\Windows\System32\WindowsPowerShell"
                        r"\v1.0\powershell.exe"
                    ),
                    "command_line": "powershell.exe -EncodedCommand AAA",
                    "owner": "LAB\\alice",
                }
            ],
        )
        return path

    def test_process_case_runs_selected_tool_and_persists_records(self) -> None:
        self.seed_event_log()
        service = IntegrationService(
            self.temp_path,
            adapter_factory=self.factory,
            actor="test",
        )

        result = service.process_case(
            self.case.case_id,
            tool_ids=("evtxecmd", "evtxecmd"),
            verify_integrity=False,
        )

        self.assertEqual(result.requested_tools, ("evtxecmd",))
        self.assertEqual(result.succeeded_tools, ("evtxecmd",))
        self.assertEqual(result.parsed_record_count, 1)
        self.assertEqual(result.normalized_count, 1)
        self.assertEqual(result.timeline_count, 1)
        self.assertTrue(result.records_path.is_file())
        self.assertTrue(result.timeline_path.is_file())
        self.assertFalse(self.adapters["evtxecmd"].verify_integrity)
        records = ProcessingPipeline(self.temp_path).load_records(self.case.case_id)
        self.assertEqual(records[0].hostname, "WIN-LAB01")

    def test_process_case_uses_profile_tools(self) -> None:
        self.seed_event_log()
        result = IntegrationService(
            self.temp_path,
            adapter_factory=self.factory,
        ).process_case(
            self.case.case_id,
            verify_integrity=False,
        )

        self.assertEqual(
            result.requested_tools,
            ("hayabusa", "evtxecmd"),
        )
        self.assertEqual(
            result.succeeded_tools,
            ("hayabusa", "evtxecmd"),
        )
        self.assertEqual(result.parsed_record_count, 2)

    def test_progress_reports_tools_skips_pipeline_and_completion(self) -> None:
        self.seed_event_log()
        messages = []
        result = IntegrationService(
            self.temp_path,
            adapter_factory=self.factory,
        ).process_case(
            self.case.case_id,
            tool_ids=("evtxecmd", "pecmd"),
            verify_integrity=False,
            on_progress=messages.append,
        )

        self.assertEqual(result.succeeded_tools, ("evtxecmd",))
        self.assertEqual(result.skipped_tools, ("pecmd",))
        self.assertTrue(any("Công cụ 1/2: evtxecmd" in msg for msg in messages))
        self.assertTrue(any("Bỏ qua: pecmd" in msg for msg in messages))
        self.assertTrue(any("loại bỏ bản ghi trùng" in msg for msg in messages))
        self.assertTrue(any("lưu dữ liệu chuẩn hóa" in msg for msg in messages))
        self.assertIn("1 cảnh báo", messages[-1])

    def test_failed_tool_reports_error_without_false_completion(self) -> None:
        self.seed_event_log()
        messages = []
        service = IntegrationService(
            self.temp_path,
            adapter_factory=lambda definition, runner: FakeAdapter(
                definition,
                runner,
                status=ToolRunStatus.FAILED,
            ),
        )
        with self.assertRaises(ToolIntegrationError):
            service.process_case(
                self.case.case_id,
                tool_ids=("evtxecmd",),
                verify_integrity=False,
                on_progress=messages.append,
            )

        self.assertTrue(any("Thất bại: evtxecmd" in msg for msg in messages))
        self.assertFalse(any("Xử lý hoàn tất" in msg for msg in messages))

    def test_process_case_merges_live_data_with_tool_records(self) -> None:
        self.seed_event_log()
        self.seed_live_process()
        from evidence.evidence_service import EvidenceService

        EvidenceService(self.temp_path).preserve_case(self.case.case_id)
        result = IntegrationService(
            self.temp_path,
            adapter_factory=self.factory,
        ).process_case(
            self.case.case_id,
            tool_ids=("evtxecmd",),
            verify_integrity=False,
        )

        self.assertEqual(result.live_record_count, 1)
        self.assertEqual(result.parsed_record_count, 2)
        self.assertEqual(result.normalized_count, 2)
        records = ProcessingPipeline(self.temp_path).load_records(self.case.case_id)
        live = next(
            record for record in records if record.source_type == "live_process"
        )
        self.assertEqual(live.process_name, "powershell.exe")
        self.assertEqual(
            live.raw_reference,
            "acquisition/live/processes.json",
        )
        analysis = AnalysisService(self.temp_path).analyze(
            case_id=self.case.case_id,
            persist=False,
        )
        self.assertIn(
            "suspicious_powershell",
            {alert.rule_id for alert in analysis.alerts},
        )

    def test_missing_artifact_does_not_overwrite_existing_records(self) -> None:
        sentinel = self.paths.normalized / "records.json"
        sentinel.write_text("keep-existing-data", encoding="utf-8")
        service = IntegrationService(
            self.temp_path,
            adapter_factory=self.factory,
        )

        with self.assertRaisesRegex(
            ToolIntegrationError,
            "không bị ghi đè",
        ):
            service.process_case(
                self.case.case_id,
                tool_ids=("pecmd",),
                verify_integrity=False,
            )

        self.assertEqual(
            sentinel.read_text(encoding="utf-8"),
            "keep-existing-data",
        )

    def test_amcache_requires_the_expected_hive_name(self) -> None:
        directory = self.paths.raw_artifact_dir("amcache")
        (directory / "other.hve").write_bytes(b"hive")

        with self.assertRaisesRegex(
            ToolIntegrationError,
            "Không có bản ghi nào",
        ):
            IntegrationService(
                self.temp_path,
                adapter_factory=self.factory,
            ).process_case(
                self.case.case_id,
                tool_ids=("amcacheparser",),
                verify_integrity=False,
            )

    def test_failed_tool_can_be_followed_by_a_successful_tool(self) -> None:
        self.seed_event_log()

        def factory(definition, runner):
            status = (
                ToolRunStatus.FAILED
                if definition.tool_id == "hayabusa"
                else ToolRunStatus.SUCCEEDED
            )
            return FakeAdapter(
                definition,
                runner,
                status=status,
            )

        result = IntegrationService(
            self.temp_path,
            adapter_factory=factory,
        ).process_case(
            self.case.case_id,
            verify_integrity=False,
        )

        self.assertEqual(result.failed_tools, ("hayabusa",))
        self.assertEqual(result.succeeded_tools, ("evtxecmd",))
        self.assertEqual(result.normalized_count, 1)


if __name__ == "__main__":
    unittest.main()
