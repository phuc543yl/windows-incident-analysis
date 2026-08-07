from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from case_management.case_service import CaseService
from common.enums import ArtifactType, ToolRunStatus
from common.exceptions import ConfigurationError, ToolIntegrationError
from integrations.adapters import ADAPTER_TYPES, create_adapter
from integrations.parsers import (
    AmcacheParserParser,
    EvtxECmdParser,
    HayabusaParser,
    MFTECmdParser,
    PECmdParser,
    RECmdParser,
)
from integrations.tool_registry import ToolRegistry
from integrations.tool_runner import ToolRunner
from integrations.tool_validator import ToolValidator

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class IntegrationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.service = CaseService(self.temp_path, actor="analyst")
        self.case = self.service.create_case(
            title="Integration test",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )
        self.paths = self.service.repository.paths(self.case.case_id)
        self.registry = ToolRegistry(self.temp_path)
        for definition in self.registry.list():
            executable = definition.executable_path(self.temp_path)
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"test executable")
        self.runner = ToolRunner(
            self.temp_path,
            registry=self.registry,
            validator=ToolValidator(self.registry),
        )

    def run_directory(self, name: str = "manual") -> Path:
        output = self.paths.tool_outputs / "hayabusa" / name
        output.mkdir(parents=True, exist_ok=True)
        return output


class ToolRegistryTests(IntegrationTestCase):
    def test_registry_loads_all_tools_and_filters_artifact(self) -> None:
        self.assertEqual(
            {item.tool_id for item in self.registry.list()},
            set(ADAPTER_TYPES),
        )
        self.assertEqual(
            {
                item.tool_id
                for item in self.registry.for_artifact(
                    ArtifactType.EVENT_LOGS
                )
            },
            {"hayabusa", "evtxecmd"},
        )

    def test_registry_rejects_unsafe_executable(self) -> None:
        config = {
            "schema_version": 1,
            "tools": [
                {
                    "id": "bad",
                    "name": "Bad tool",
                    "enabled": True,
                    "required_for_mvp": False,
                    "adapter": "bad",
                    "executable": "../outside.exe",
                    "supported_artifacts": ["files"],
                    "output_format": "csv",
                    "timeout_seconds": 10,
                }
            ],
        }
        path = self.temp_path / "unsafe-tools.json"
        path.write_text(json.dumps(config), encoding="utf-8")

        with self.assertRaisesRegex(
            ConfigurationError,
            "đường dẫn tương đối an toàn",
        ):
            ToolRegistry(self.temp_path, config_path=path)

    def test_registry_rejects_duplicate_tool_id(self) -> None:
        config = json.loads(
            (self.temp_path / "config" / "tool_integrations.json")
            .read_text(encoding="utf-8")
        )
        config["tools"].append(dict(config["tools"][0]))
        path = self.temp_path / "duplicate-tools.json"
        path.write_text(json.dumps(config), encoding="utf-8")

        with self.assertRaisesRegex(ConfigurationError, "Trùng tool id"):
            ToolRegistry(self.temp_path, config_path=path)

    def test_registry_reports_missing_and_disabled_tool(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "Không tìm thấy"):
            self.registry.get("unknown")
        disabled = replace(
            self.registry.get("hayabusa"),
            enabled=False,
        )
        self.assertFalse(disabled.enabled)


class ToolValidatorTests(IntegrationTestCase):
    def test_validator_accepts_existing_executable(self) -> None:
        result = ToolValidator(self.registry).validate("hayabusa")

        self.assertTrue(result.valid)
        self.assertTrue(result.available)
        self.assertEqual(result.errors, ())

    def test_validator_reports_missing_executable(self) -> None:
        definition = self.registry.get("hayabusa")
        definition.executable_path(self.temp_path).unlink()

        result = ToolValidator(self.registry).validate(definition)

        self.assertFalse(result.valid)
        self.assertFalse(result.available)
        self.assertIn("Không tìm thấy executable.", result.errors)

    def test_validator_rejects_disabled_and_symbolic_link(self) -> None:
        validator = ToolValidator(self.registry)
        disabled = replace(
            self.registry.get("hayabusa"),
            enabled=False,
        )
        with self.assertRaisesRegex(ToolIntegrationError, "đang bị tắt"):
            validator.require_available(disabled)

        definition = self.registry.get("evtxecmd")
        executable = definition.executable_path(self.temp_path)
        target = executable.with_name("real.exe")
        executable.replace(target)
        try:
            executable.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"Không thể tạo symlink: {exc}")
        result = validator.validate(definition)
        self.assertFalse(result.valid)
        self.assertFalse(result.available)


class ToolRunnerTests(IntegrationTestCase):
    def test_runner_success_discovers_output_and_never_uses_shell(self) -> None:
        output = self.run_directory()
        (output / "hayabusa.csv").write_text(
            "Timestamp,RuleTitle\n2026-07-29T10:00:00Z,Rule\n",
            encoding="utf-8",
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="\ufeffok",
            stderr="",
        )
        with patch(
            "integrations.tool_runner.subprocess.run",
            return_value=completed,
        ) as run_mock:
            result = self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline", "-d", "input"),
                output_directory=output,
                expected_output_globs=("hayabusa.csv",),
            )

        self.assertEqual(result.status, ToolRunStatus.SUCCEEDED)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(result.output_files), 1)
        self.assertEqual((output / "stdout.txt").read_text(), "ok")
        self.assertFalse(run_mock.call_args.kwargs["shell"])
        self.assertIsInstance(run_mock.call_args.args[0], list)

    def test_runner_marks_nonzero_exit_as_failed(self) -> None:
        output = self.run_directory()
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=12,
            stdout="",
            stderr="invalid EVTX",
        )
        with patch(
            "integrations.tool_runner.subprocess.run",
            return_value=completed,
        ):
            result = self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline",),
                output_directory=output,
            )

        self.assertEqual(result.status, ToolRunStatus.FAILED)
        self.assertEqual(result.exit_code, 12)
        self.assertEqual(result.error_message, "invalid EVTX")

    def test_runner_marks_timeout(self) -> None:
        output = self.run_directory()
        timeout = subprocess.TimeoutExpired(
            cmd=["hayabusa"],
            timeout=300,
            output=b"partial",
            stderr=b"slow",
        )
        with patch(
            "integrations.tool_runner.subprocess.run",
            side_effect=timeout,
        ):
            result = self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline",),
                output_directory=output,
            )

        self.assertEqual(result.status, ToolRunStatus.TIMED_OUT)
        self.assertIsNone(result.exit_code)
        self.assertIn("timeout", result.error_message)

    def test_runner_fails_when_expected_output_is_missing(self) -> None:
        output = self.run_directory()
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="ok",
            stderr="",
        )
        with patch(
            "integrations.tool_runner.subprocess.run",
            return_value=completed,
        ):
            result = self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline",),
                output_directory=output,
                expected_output_globs=("missing.csv",),
            )

        self.assertEqual(result.status, ToolRunStatus.FAILED)
        self.assertIn("không tạo output", result.error_message)

    def test_runner_rejects_output_outside_case_and_unsafe_glob(self) -> None:
        with self.assertRaisesRegex(
            ToolIntegrationError,
            "analysis/tool_outputs",
        ):
            self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline",),
                output_directory=self.temp_path / "outside",
            )
        with self.assertRaisesRegex(ValueError, "không an toàn"):
            self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline",),
                output_directory=self.run_directory("glob"),
                expected_output_globs=("../output.csv",),
            )


class AdapterTests(IntegrationTestCase):
    def test_factory_builds_all_configured_adapters(self) -> None:
        for definition in self.registry.list():
            with self.subTest(tool_id=definition.tool_id):
                adapter = create_adapter(definition, self.runner)
                self.assertEqual(adapter.tool_id, definition.tool_id)
                self.assertEqual(adapter.parser.tool_id, definition.tool_id)

    def test_adapters_build_expected_output_and_safe_arguments(self) -> None:
        directory_input = self.temp_path / "inputs"
        directory_input.mkdir()
        file_input = directory_input / "artifact.bin"
        file_input.write_bytes(b"artifact")
        output = self.paths.tool_outputs / "commands"
        output.mkdir()

        expected = {
            "hayabusa": (directory_input, "hayabusa.csv"),
            "evtxecmd": (directory_input, "evtxecmd.csv"),
            "pecmd": (directory_input, "pecmd.csv"),
            "amcacheparser": (file_input, "amcache.csv"),
            "mftecmd": (file_input, "mftecmd.csv"),
            "recmd": (file_input, "recmd.csv"),
        }
        for tool_id, (source, output_name) in expected.items():
            with self.subTest(tool_id=tool_id):
                adapter = create_adapter(
                    self.registry.get(tool_id),
                    self.runner,
                )
                command = adapter.build_command((source,), output)
                self.assertIn(str(source), command.arguments)
                self.assertEqual(
                    command.expected_output_globs,
                    (output_name,),
                )
                self.assertNotIn("&", command.arguments)

    def test_adapter_run_verifies_integrity_before_invocation(self) -> None:
        source = self.paths.raw_artifact_dir("event_logs")
        adapter = create_adapter(
            self.registry.get("hayabusa"),
            self.runner,
        )
        with (
            patch(
                "integrations.adapters.base_adapter.IntegrityVerifier.verify"
            ) as verify_mock,
            patch.object(
                self.runner,
                "create_run_directory",
                side_effect=RuntimeError("stop after verification"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                adapter.run(
                    case_id=self.case.case_id,
                    input_paths=(source,),
                )

        verify_mock.assert_called_once_with()

    def test_adapter_rejects_missing_input(self) -> None:
        adapter = create_adapter(
            self.registry.get("hayabusa"),
            self.runner,
        )
        with self.assertRaisesRegex(ToolIntegrationError, "Không tìm thấy"):
            adapter.run(
                case_id=self.case.case_id,
                input_paths=(self.temp_path / "missing",),
                verify_integrity=False,
            )

    def test_adapter_parses_successful_tool_result(self) -> None:
        output = self.run_directory()
        csv_path = output / "hayabusa.csv"
        csv_path.write_text(
            "Timestamp,RuleTitle,Computer,EventID\n"
            "2026-07-29T10:00:00Z,Suspicious logon,WIN-1,4624\n",
            encoding="utf-8",
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        )
        with patch(
            "integrations.tool_runner.subprocess.run",
            return_value=completed,
        ):
            result = self.runner.run(
                case_id=self.case.case_id,
                tool="hayabusa",
                arguments=("csv-timeline",),
                output_directory=output,
                expected_output_globs=("hayabusa.csv",),
            )
        adapter = create_adapter(
            self.registry.get("hayabusa"),
            self.runner,
        )

        records = adapter.parse(result)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].summary, "Suspicious logon")
        self.assertEqual(records[0].event_id, 4624)


class ParserTests(IntegrationTestCase):
    def test_all_parsers_map_representative_csv_rows(self) -> None:
        cases = (
            (
                HayabusaParser(),
                "Timestamp,RuleTitle,EventID\n"
                "2026-07-29T01:00:00Z,Rule A,4624\n",
                ArtifactType.EVENT_LOGS,
                "Rule A",
            ),
            (
                EvtxECmdParser(),
                "TimeCreated,Provider,EventId\n"
                "2026-07-29T02:00:00Z,Security,4688\n",
                ArtifactType.EVENT_LOGS,
                "Security event 4688",
            ),
            (
                PECmdParser(),
                "LastRun,ExecutableName,SourceFilename\n"
                "2026-07-29T03:00:00Z,POWERSHELL.EXE,powershell.pf\n",
                ArtifactType.PREFETCH,
                "Prefetch execution: POWERSHELL.EXE",
            ),
            (
                AmcacheParserParser(),
                "FileKeyLastWriteTimestamp,Name,FullPath\n"
                "2026-07-29T04:00:00Z,bad.exe,C:\\Temp\\bad.exe\n",
                ArtifactType.AMCACHE,
                "Amcache entry: bad.exe",
            ),
            (
                MFTECmdParser(),
                "Modified0x10,FileName,FullPath\n"
                "2026-07-29T05:00:00Z,note.txt,C:\\Temp\\note.txt\n",
                ArtifactType.MFT,
                "MFT entry:",
            ),
            (
                RECmdParser(),
                "LastWriteTimestamp,KeyPath,ValueName\n"
                "2026-07-29T06:00:00Z,HKLM\\Software\\Run,Bad\n",
                ArtifactType.REGISTRY,
                "Registry entry:",
            ),
        )
        for parser, text, artifact_type, summary in cases:
            with self.subTest(tool_id=parser.tool_id):
                path = self.temp_path / f"{parser.tool_id}.csv"
                path.write_text(text, encoding="utf-8")
                records = parser.parse(
                    path,
                    case_id=self.case.case_id,
                    hostname="WIN-LAB01",
                    raw_reference=f"analysis/{path.name}",
                )
                self.assertEqual(len(records), 1)
                self.assertEqual(
                    records[0].artifact_type,
                    artifact_type,
                )
                self.assertIn(summary, records[0].summary)
                self.assertEqual(records[0].hostname, "WIN-LAB01")

    def test_parser_supports_utf16_csv(self) -> None:
        path = self.temp_path / "utf16.csv"
        path.write_text(
            "Timestamp,RuleTitle\n"
            "2026-07-29T07:00:00Z,Unicode rule\n",
            encoding="utf-16",
        )

        records = HayabusaParser().parse(
            path,
            case_id=self.case.case_id,
        )

        self.assertEqual(records[0].summary, "Unicode rule")

    def test_parser_supports_json_and_jsonl(self) -> None:
        json_path = self.temp_path / "events.json"
        json_path.write_text(
            json.dumps(
                {
                    "records": [
                        {
                            "Timestamp": "2026-07-29T08:00:00Z",
                            "RuleTitle": "JSON rule",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        jsonl_path = self.temp_path / "events.jsonl"
        jsonl_path.write_text(
            json.dumps(
                {
                    "Timestamp": "2026-07-29T09:00:00Z",
                    "RuleTitle": "JSONL rule",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        parser = HayabusaParser()
        self.assertEqual(
            parser.parse(json_path, case_id=self.case.case_id)[0].summary,
            "JSON rule",
        )
        self.assertEqual(
            parser.parse(jsonl_path, case_id=self.case.case_id)[0].summary,
            "JSONL rule",
        )

    def test_parser_reports_invalid_timestamp_with_record_number(self) -> None:
        path = self.temp_path / "invalid.csv"
        path.write_text(
            "Timestamp,RuleTitle\nnot-a-date,Bad row\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ToolIntegrationError,
            "record 1.*Timestamp",
        ):
            HayabusaParser().parse(
                path,
                case_id=self.case.case_id,
            )

    def test_parser_rejects_unsupported_extension(self) -> None:
        path = self.temp_path / "events.txt"
        path.write_text("not supported", encoding="utf-8")

        with self.assertRaisesRegex(
            ToolIntegrationError,
            "chưa được hỗ trợ",
        ):
            HayabusaParser().parse(
                path,
                case_id=self.case.case_id,
            )


if __name__ == "__main__":
    unittest.main()
