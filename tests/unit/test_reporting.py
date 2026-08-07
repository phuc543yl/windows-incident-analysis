from __future__ import annotations

import csv
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_service import CaseService
from common.exceptions import ReportError
from common.json_utils import append_jsonl, read_json_object, write_json
from evidence.manifest_builder import ManifestBuilder
from reporting.exporters import (
    CsvExporter,
    HtmlExporter,
    JsonExporter,
    PdfExporter,
)
from reporting.report_builder import ReportBuilder
from reporting.report_context import ReportContextBuilder
from reporting.report_service import ReportResult, ReportService

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ReportingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(PROJECT_ROOT / "config", self.temp_path / "config")
        self.case_service = CaseService(self.temp_path, actor="analyst")
        self.case = self.case_service.create_case(
            title="Điều tra máy chủ <WIN-LAB01>",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
            description="Kiểm tra dấu hiệu xâm nhập.",
            hypothesis="PowerShell tạo persistence.",
        )
        self.paths = self.case_service.repository.paths(self.case.case_id)

    def seed_report_data(self) -> None:
        raw_file = (
            self.paths.raw_artifact_dir("event_logs") / "Security.evtx"
        )
        raw_file.write_bytes(b"EVTX evidence")
        manifest = ManifestBuilder(
            self.case.case_id,
            self.temp_path,
        ).build(collected_by="analyst")
        evidence_id = manifest["evidence_items"][0]["evidence_id"]
        append_jsonl(
            self.paths.collection_log,
            {
                "case_id": self.case.case_id,
                "collector_id": "event_logs",
                "status": "succeeded",
                "started_at": "2026-07-29T08:00:00.000Z",
                "finished_at": "2026-07-29T08:01:00.000Z",
                "record_count": 1,
            },
        )
        append_jsonl(
            self.paths.tool_runs_log,
            {
                "case_id": self.case.case_id,
                "tool_id": "hayabusa",
                "tool_result_id": "TOOL-001",
                "status": "succeeded",
                "started_at": "2026-07-29T08:02:00.000Z",
                "exit_code": 0,
                "command": ["hayabusa.exe", "--token", "secret"],
                "output_files": ["analysis/tool_outputs/timeline.csv"],
            },
        )
        finding = {
            "case_id": self.case.case_id,
            "finding_id": "FIND-001",
            "title": "PowerShell đáng ngờ",
            "description": "EncodedCommand được sử dụng.",
            "severity": "high",
            "mitre_techniques": ["T1059.001"],
            "evidence_item_ids": [evidence_id],
        }
        alert = {
            "case_id": self.case.case_id,
            "alert_id": "ALERT-001",
            "rule_id": "suspicious_powershell",
            "title": "PowerShell đáng ngờ",
            "description": "Rule phát hiện PowerShell.",
            "severity": "high",
            "risk_score": 85,
            "finding_ids": ["FIND-001"],
            "recommendation": "Kiểm tra script.",
        }
        incident = {
            "case_id": self.case.case_id,
            "incident_id": "INC-001",
            "title": "Endpoint compromise",
            "description": "Chuỗi hành vi xâm nhập.",
            "status": "confirmed",
            "confidence_score": 0.9,
            "finding_ids": ["FIND-001"],
            "alert_ids": ["ALERT-001"],
            "timeline_event_ids": ["TL-001"],
            "cia_impacts": ["integrity"],
            "analyst_conclusion": "Sự cố đã được xác nhận.",
            "recommendations": ["Cô lập theo quy trình phê duyệt."],
        }
        timeline = {
            "case_id": self.case.case_id,
            "timeline_event_id": "TL-001",
            "timestamp": "2026-07-29T08:03:00.000Z",
            "event_type": "process_execution",
            "hostname": "WIN-LAB01",
            "user": "alice",
            "summary": "powershell.exe -EncodedCommand",
            "source_record_ids": ["REC-001"],
            "finding_ids": ["FIND-001"],
            "alert_ids": ["ALERT-001"],
            "evidence_item_ids": [evidence_id],
            "details": {"process_id": 1200},
        }
        for path, key, values in (
            (self.paths.findings_json, "findings", [finding]),
            (self.paths.alerts_json, "alerts", [alert]),
            (self.paths.incidents_json, "incidents", [incident]),
            (self.paths.timeline_json, "timeline", [timeline]),
        ):
            write_json(
                path,
                {
                    "schema_version": 1,
                    "case_id": self.case.case_id,
                    key: values,
                },
            )
        write_json(
            self.paths.notes_json,
            {
                "case_id": self.case.case_id,
                "notes": [
                    {
                        "text": "Đối chiếu EVTX với timeline.",
                        "author": "analyst",
                    }
                ],
            },
        )
        write_json(
            self.paths.conclusion_json,
            {
                "case_id": self.case.case_id,
                "conclusion": "Sự cố ảnh hưởng Integrity.",
                "cia_impacts": ["integrity"],
            },
        )
        write_json(
            self.paths.recommendations_json,
            {
                "case_id": self.case.case_id,
                "recommendations": [
                    "Đổi thông tin xác thực.",
                    "Rà soát persistence.",
                ],
            },
        )

    def build_report(self):
        self.seed_report_data()
        context = ReportContextBuilder(self.temp_path).build(
            self.case.case_id
        )
        return ReportBuilder().build(
            context,
            generated_at=datetime(
                2026,
                7,
                29,
                9,
                tzinfo=timezone.utc,
            ),
        )


class ReportContextTests(ReportingTestCase):
    def test_empty_optional_data_is_supported(self) -> None:
        context = ReportContextBuilder(self.temp_path).build(
            self.case.case_id
        )

        self.assertEqual(context.case_id, self.case.case_id)
        self.assertEqual(context.manifest["item_count"], 0)
        self.assertEqual(context.findings, ())
        self.assertEqual(context.recommendations, ())

    def test_build_loads_every_report_section(self) -> None:
        self.seed_report_data()

        context = ReportContextBuilder(self.temp_path).build(
            self.case.case_id
        )

        self.assertEqual(len(context.manifest["evidence_items"]), 1)
        self.assertEqual(context.tool_runs[0]["tool_id"], "hayabusa")
        self.assertEqual(context.findings[0]["finding_id"], "FIND-001")
        self.assertEqual(context.alerts[0]["alert_id"], "ALERT-001")
        self.assertEqual(context.incidents[0]["incident_id"], "INC-001")
        self.assertEqual(context.timeline[0]["timeline_event_id"], "TL-001")
        self.assertEqual(len(context.analyst_notes), 1)
        self.assertEqual(len(context.recommendations), 2)

    def test_build_rejects_foreign_case_envelope(self) -> None:
        write_json(
            self.paths.findings_json,
            {"case_id": "CASE-20260729-999", "findings": []},
        )

        with self.assertRaisesRegex(ReportError, "không khớp Case"):
            ReportContextBuilder(self.temp_path).build(self.case.case_id)

    def test_build_rejects_invalid_jsonl(self) -> None:
        self.paths.tool_runs_log.write_text("{broken\n", encoding="utf-8")

        with self.assertRaisesRegex(ReportError, "dòng 1"):
            ReportContextBuilder(self.temp_path).build(self.case.case_id)

    def test_string_notes_and_list_recommendations_are_supported(self) -> None:
        write_json(
            self.paths.notes_json,
            {"case_id": self.case.case_id, "notes": ["Ghi chú nhanh"]},
        )
        write_json(
            self.paths.recommendations_json,
            ["Khóa tài khoản theo quy trình."],
        )

        context = ReportContextBuilder(self.temp_path).build(
            self.case.case_id
        )

        self.assertEqual(context.analyst_notes[0]["text"], "Ghi chú nhanh")
        self.assertEqual(
            context.recommendations,
            ("Khóa tài khoản theo quy trình.",),
        )


class ReportBuilderTests(ReportingTestCase):
    def test_builder_creates_required_sections_and_counts(self) -> None:
        report = self.build_report()

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["generated_at"],
            "2026-07-29T09:00:00.000Z",
        )
        self.assertEqual(report["scope"]["profile_id"], self.case.profile_id)
        self.assertEqual(report["summary"]["evidence_count"], 1)
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["timeline_event_count"], 1)
        self.assertEqual(
            report["analyst"]["recommendations"][0],
            "Đổi thông tin xác thực.",
        )

    def test_builder_removes_tool_command_arguments(self) -> None:
        report = self.build_report()

        tool_run = report["execution"]["tool_runs"][0]
        self.assertNotIn("command", tool_run)
        self.assertEqual(tool_run["tool_id"], "hayabusa")


class ExporterTests(ReportingTestCase):
    def test_json_exporter_round_trip(self) -> None:
        report = self.build_report()
        output = self.temp_path / "out" / "report.json"

        result = JsonExporter().export(report, output)

        self.assertEqual(result, output)
        loaded = read_json_object(output)
        self.assertEqual(loaded["case"]["case_id"], self.case.case_id)
        self.assertEqual(loaded["summary"]["incident_count"], 1)

    def test_csv_exporter_writes_excel_friendly_timeline(self) -> None:
        report = self.build_report()
        output = self.temp_path / "out" / "timeline.csv"

        CsvExporter().export(report["analysis"]["timeline"], output)

        self.assertTrue(output.read_bytes().startswith(b"\xef\xbb\xbf"))
        with output.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["timeline_event_id"], "TL-001")
        self.assertEqual(rows[0]["finding_ids"], "FIND-001")
        self.assertEqual(
            json.loads(rows[0]["details_json"])["process_id"],
            1200,
        )

    def test_csv_exporter_rejects_non_object_event(self) -> None:
        with self.assertRaisesRegex(ReportError, "object"):
            CsvExporter().export(
                ["invalid"],
                self.temp_path / "timeline.csv",
            )

    def test_html_exporter_is_self_contained_and_escapes_input(self) -> None:
        report = self.build_report()
        output = self.temp_path / "out" / "report.html"

        HtmlExporter().export(report, output)

        content = output.read_text(encoding="utf-8")
        self.assertIn("<!doctype html>", content)
        self.assertIn("CROW-EYE", content)
        self.assertIn("&lt;WIN-LAB01&gt;", content)
        self.assertIn("FIND-001", content)
        self.assertIn("Integrity", content)
        self.assertNotIn("<script", content)

    def test_html_exporter_rejects_missing_template(self) -> None:
        with self.assertRaisesRegex(ReportError, "template"):
            HtmlExporter(self.temp_path / "missing").export(
                self.build_report(),
                self.temp_path / "report.html",
            )

    def test_pdf_exporter_creates_pdf(self) -> None:
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab chưa được cài.")
        output = self.temp_path / "out" / "report.pdf"

        PdfExporter().export(self.build_report(), output)

        self.assertTrue(output.read_bytes().startswith(b"%PDF-"))
        self.assertGreater(output.stat().st_size, 1000)


class ReportServiceTests(ReportingTestCase):
    def test_generate_creates_only_requested_formats(self) -> None:
        self.seed_report_data()

        result = ReportService(
            self.temp_path,
            actor="analyst",
        ).generate(self.case.case_id, formats=("json", "csv", "json"))

        self.assertEqual(result.formats, ("json", "csv"))
        self.assertEqual(
            result.path_for("json").name,
            "investigation_report.json",
        )
        self.assertEqual(result.path_for("csv").name, "timeline.csv")
        self.assertFalse(
            (self.paths.reports / "investigation_report.html").exists()
        )

    def test_generate_all_formats_and_audits(self) -> None:
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab chưa được cài.")
        self.seed_report_data()

        result = ReportService(
            self.temp_path,
            actor="analyst",
        ).generate(self.case.case_id)

        self.assertEqual(
            set(result.output_paths),
            {"html", "pdf", "json", "csv"},
        )
        self.assertTrue(all(path.is_file() for path in result.output_paths.values()))
        audit = AuditLogger(
            self.case.case_id,
            self.temp_path,
        ).read_entries()
        self.assertEqual(audit[-1]["action"], "report_generated")
        self.assertEqual(
            audit[-1]["details"]["formats"],
            ["html", "pdf", "json", "csv"],
        )

    def test_generate_accepts_single_format_string(self) -> None:
        result = ReportService(self.temp_path).generate(
            self.case.case_id,
            formats="json",
        )

        self.assertEqual(result.formats, ("json",))

    def test_generate_rejects_invalid_or_empty_formats(self) -> None:
        service = ReportService(self.temp_path)
        with self.subTest("invalid"):
            with self.assertRaisesRegex(ReportError, "không được hỗ trợ"):
                service.generate(self.case.case_id, ("docx",))
        with self.subTest("empty"):
            with self.assertRaisesRegex(ReportError, "ít nhất"):
                service.generate(self.case.case_id, ())

    def test_result_rejects_format_not_generated(self) -> None:
        result = ReportResult(
            case_id=self.case.case_id,
            formats=("json",),
            output_paths={"json": self.paths.reports / "report.json"},
        )

        with self.assertRaisesRegex(ReportError, "chưa được tạo"):
            result.path_for("pdf")


if __name__ == "__main__":
    unittest.main()
