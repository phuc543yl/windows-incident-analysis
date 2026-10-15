from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import dfir_cli


class CliTests(unittest.TestCase):
    def test_preserve_without_rebuild_keeps_existing_hash_reference(self) -> None:
        service = Mock()
        service.ensure_preserved.return_value = {"item_count": 1}
        code, output, error, _ = self.run_cli(
            ["preserve", "CASE-20260729-001"], service
        )
        self.assertEqual(code, dfir_cli.EXIT_OK)
        self.assertEqual(error, "")
        self.assertEqual(json.loads(output)["item_count"], 1)
        service.ensure_preserved.assert_called_once_with("CASE-20260729-001")
        service.preserve_case.assert_not_called()

    def run_cli(self, argv, service):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("dfir_cli._load_service", return_value=service) as loader,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = dfir_cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue(), loader

    def test_preserve_passes_rebuild_and_project_root(self) -> None:
        service = Mock()
        service.preserve_case.return_value = {"item_count": 1}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, output, error, loader = self.run_cli(
                [
                    "--root",
                    str(root),
                    "preserve",
                    "CASE-20260729-001",
                    "--rebuild",
                ],
                service,
            )

        self.assertEqual(code, dfir_cli.EXIT_OK)
        self.assertEqual(error, "")
        self.assertEqual(json.loads(output)["item_count"], 1)
        loader.assert_called_once_with(
            "evidence.evidence_service",
            "EvidenceService",
            root,
        )
        service.preserve_case.assert_called_once_with(
            "CASE-20260729-001",
            rebuild=True,
        )

    def test_process_accepts_repeated_tools_and_stop_on_error(self) -> None:
        service = Mock()
        service.process_case.return_value = {"normalized_count": 2}

        code, _, _, _ = self.run_cli(
            [
                "process",
                "CASE-20260729-001",
                "--tool",
                "hayabusa",
                "--tool",
                "evtxecmd",
                "--stop-on-error",
            ],
            service,
        )

        self.assertEqual(code, dfir_cli.EXIT_OK)
        service.process_case.assert_called_once_with(
            "CASE-20260729-001",
            tool_ids=("hayabusa", "evtxecmd"),
            continue_on_error=False,
        )

    def test_process_uses_profile_when_tool_is_not_given(self) -> None:
        service = Mock()
        service.process_case.return_value = {"normalized_count": 1}

        code, _, _, _ = self.run_cli(
            ["process", "CASE-20260729-001"],
            service,
        )

        self.assertEqual(code, dfir_cli.EXIT_OK)
        service.process_case.assert_called_once_with(
            "CASE-20260729-001",
            tool_ids=None,
            continue_on_error=True,
        )

    def test_analyze_calls_existing_service_method(self) -> None:
        service = Mock()
        service.analyze.return_value = {"alert_count": 3}

        code, output, _, _ = self.run_cli(
            ["analyze", "CASE-20260729-001"],
            service,
        )

        self.assertEqual(code, dfir_cli.EXIT_OK)
        self.assertEqual(json.loads(output)["alert_count"], 3)
        service.analyze.assert_called_once_with(case_id="CASE-20260729-001")

    def test_report_calls_generate_with_default_formats(self) -> None:
        service = Mock()
        service.generate.return_value = {"formats": ["html", "json"]}

        code, _, _, _ = self.run_cli(
            ["report", "CASE-20260729-001"],
            service,
        )

        self.assertEqual(code, dfir_cli.EXIT_OK)
        service.generate.assert_called_once_with(
            "CASE-20260729-001",
            formats=("html", "json"),
        )

    def test_report_preserves_requested_format_order(self) -> None:
        service = Mock()
        service.generate.return_value = {"formats": ["json", "csv"]}

        code, _, _, _ = self.run_cli(
            [
                "report",
                "CASE-20260729-001",
                "--format",
                "json",
                "--format",
                "csv",
            ],
            service,
        )

        self.assertEqual(code, dfir_cli.EXIT_OK)
        service.generate.assert_called_once_with(
            "CASE-20260729-001",
            formats=("json", "csv"),
        )

    def test_expected_value_error_returns_usage_code(self) -> None:
        service = Mock()
        service.verify_case.side_effect = ValueError("invalid case")

        code, _, error, _ = self.run_cli(
            ["verify", "CASE-20260729-001"],
            service,
        )

        self.assertEqual(code, dfir_cli.EXIT_USAGE)
        self.assertIn("invalid case", error)


if __name__ == "__main__":
    unittest.main()
