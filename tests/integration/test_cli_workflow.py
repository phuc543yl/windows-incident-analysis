from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import dfir_cli
from case_management.case_service import CaseService
from integrations.tool_registry import ToolRegistry
from processing.processing_pipeline import ProcessingPipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class CliWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(PROJECT_ROOT / "config", self.root / "config")

    def run_cli(self, *arguments: str) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = dfir_cli.main(
                ["--root", str(self.root), *arguments]
            )
        self.assertEqual(code, dfir_cli.EXIT_OK, stderr.getvalue())
        return json.loads(stdout.getvalue())

    def test_case_to_report_workflow_through_cli(self) -> None:
        created = self.run_cli(
            "case",
            "create",
            "--title",
            "CLI integration workflow",
            "--target",
            "WIN-LAB01",
            "--profile",
            "account_compromise",
        )
        case_id = created["case_id"]
        repository = CaseService(self.root).repository
        paths = repository.paths(case_id)
        (paths.raw_artifact_dir("event_logs") / "Security.evtx").write_bytes(
            b"synthetic evtx"
        )

        preserved = self.run_cli("preserve", case_id)
        self.assertEqual(preserved["item_count"], 1)
        verified = self.run_cli("verify", case_id)
        self.assertTrue(verified["success"])

        definition = ToolRegistry(self.root).get("evtxecmd")
        executable = definition.executable_path(self.root)
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"test executable")

        def fake_run(command, **kwargs):
            output_directory = Path(
                command[command.index("--csv") + 1]
            )
            output_name = command[command.index("--csvf") + 1]
            (output_directory / output_name).write_text(
                "TimeCreated,EventId,Computer,UserName,Provider,Payload\n"
                "2026-07-29T08:00:00Z,4625,WIN-LAB01,alice,"
                "Microsoft-Windows-Security-Auditing,Failed logon\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(
                command,
                returncode=0,
                stdout="processed",
                stderr="",
            )

        with patch(
            "integrations.tool_runner.subprocess.run",
            side_effect=fake_run,
        ):
            processed = self.run_cli(
                "process",
                case_id,
                "--tool",
                "evtxecmd",
            )

        self.assertEqual(processed["normalized_count"], 1)
        self.assertEqual(
            len(ProcessingPipeline(self.root).load_records(case_id)),
            1,
        )

        analyzed = self.run_cli("analyze", case_id)
        self.assertEqual(analyzed["record_count"], 1)
        reported = self.run_cli(
            "report",
            case_id,
            "--format",
            "html",
            "--format",
            "json",
        )
        self.assertEqual(reported["formats"], ["html", "json"])
        self.assertTrue(
            (paths.reports / "investigation_report.html").is_file()
        )
        self.assertTrue(
            (paths.reports / "investigation_report.json").is_file()
        )


if __name__ == "__main__":
    unittest.main()
