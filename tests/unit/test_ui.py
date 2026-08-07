from __future__ import annotations

import shutil
import tempfile
import tkinter as tk
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from case_management.case_service import CaseService
from common.exceptions import ProcessingError
from ui.components.data_table import Column, DataTable, normalize_cell
from ui.controllers import (
    AnalysisController,
    CaseController,
    CollectionController,
    CurrentCaseRequiredError,
    IntegrationController,
    ReportController,
)
from ui.main_window import run_dashboard
from ui.timeline_filter import TimelineFilter, filter_timeline_events
from ui.tabs import (
    AgentTab,
    AnalysisTab,
    CaseTab,
    CollectionTab,
    EvidenceTab,
    ReportTab,
    TimelineTab,
)
from ui.tabs.case_tab import _split_values

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASE_ID = "CASE-20260729-001"


@dataclass
class FakeModel:
    values: dict

    def to_dict(self):
        return dict(self.values)


class FakeCaseService:
    def __init__(self) -> None:
        self.created = None
        self.updated = None
        self.closed = None
        self.context = {
            "case": {
                "case_id": CASE_ID,
                "title": "UI test",
                "status": "open",
            },
            "target": {"hostname": "WIN-LAB01"},
            "collection_plan": {
                "case_id": CASE_ID,
                "mode": "local",
            },
            "paths": {},
        }

    def list_cases(self, status=None):
        values = dict(self.context["case"])
        if status is not None:
            values["status_filter"] = status
        return [FakeModel(values)]

    def create_case(self, **values):
        self.created = values
        return SimpleNamespace(case_id=CASE_ID)

    def get_case_context(self, case_id):
        if case_id != CASE_ID:
            raise ValueError("unknown case")
        return self.context

    def update_case(self, case_id, **changes):
        self.updated = (case_id, changes)

    def close_case(self, case_id, conclusion=""):
        self.closed = (case_id, conclusion)
        self.context["case"]["status"] = "closed"


class CaseControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = FakeCaseService()
        self.notifications = []
        self.controller = CaseController(
            service=self.service,
            on_case_changed=self.notifications.append,
        )

    def test_create_selects_case_and_notifies(self) -> None:
        context = self.controller.create_case(
            title="Case mới",
            target_hostname="WIN-LAB01",
        )

        self.assertEqual(self.service.created["title"], "Case mới")
        self.assertEqual(self.controller.current_case_id, CASE_ID)
        self.assertEqual(context["case"]["case_id"], CASE_ID)
        self.assertEqual(self.notifications[-1], context)

    def test_select_normalizes_case_id(self) -> None:
        context = self.controller.select_case("  case-20260729-001 ")

        self.assertEqual(context["case"]["title"], "UI test")
        self.assertEqual(self.controller.require_case_id(), CASE_ID)

    def test_update_and_close_current(self) -> None:
        self.controller.select_case(CASE_ID)

        self.controller.update_current(title="Đã đổi")
        self.controller.close_current("Đã hoàn tất")

        self.assertEqual(
            self.service.updated,
            (CASE_ID, {"title": "Đã đổi"}),
        )
        self.assertEqual(
            self.service.closed,
            (CASE_ID, "Đã hoàn tất"),
        )
        self.assertEqual(self.controller.current_context["case"]["status"], "closed")

    def test_current_case_is_required(self) -> None:
        with self.assertRaisesRegex(CurrentCaseRequiredError, "tạo hoặc mở"):
            self.controller.require_case_id()

    def test_list_cases_serializes_models(self) -> None:
        cases = self.controller.list_cases(status="open")

        self.assertEqual(cases[0]["case_id"], CASE_ID)
        self.assertEqual(cases[0]["status_filter"], "open")

    def test_clear_selection(self) -> None:
        self.controller.select_case(CASE_ID)
        self.controller.clear_selection()

        self.assertIsNone(self.controller.current_case_id)
        self.assertIsNone(self.controller.current_context)

    def test_real_service_controller_creates_case_layout(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        shutil.copytree(PROJECT_ROOT / "config", root / "config")
        controller = CaseController(
            service=CaseService(root, actor="analyst")
        )

        context = controller.create_case(
            title="Case UI thật",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )

        self.assertTrue(
            Path(context["paths"]["reports"]).is_dir()
        )
        self.assertEqual(controller.current_case_id, context["case"]["case_id"])


class CollectionControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_controller = CaseController(service=FakeCaseService())
        self.case_controller.select_case(CASE_ID)

    def test_collect_serializes_results_and_forwards_mode(self) -> None:
        result = FakeModel(
            {
                "result_id": "COLLECT-001",
                "status": "succeeded",
                "collector_id": "system",
            }
        )
        service = Mock()
        service.collect_case.return_value = [result]
        controller = CollectionController(
            self.case_controller,
            service=service,
        )

        records = controller.collect(mode="agent", agent_id="AGENT-01")

        service.collect_case.assert_called_once_with(
            CASE_ID,
            mode="agent",
            agent_id="AGENT-01",
        )
        self.assertEqual(records[0]["collector_id"], "system")

    def test_summarize_counts_partial_as_success(self) -> None:
        summary = CollectionController.summarize(
            (
                {"status": "succeeded"},
                {"status": "partial"},
                {"status": "failed"},
            )
        )

        self.assertEqual(
            summary,
            {"total": 3, "succeeded": 2, "failed": 1},
        )

    def test_close_releases_service(self) -> None:
        service = Mock()
        controller = CollectionController(
            self.case_controller,
            service=service,
        )

        controller.close()

        service.close.assert_called_once_with()


class AnalysisControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_controller = CaseController(service=FakeCaseService())
        self.case_controller.select_case(CASE_ID)
        self.finding = FakeModel({"finding_id": "FIND-001"})
        self.alert = FakeModel({"alert_id": "ALERT-001"})
        self.incident = FakeModel({"incident_id": "INC-001"})
        self.timeline = FakeModel({"timeline_event_id": "TL-001"})

    def test_analyze_returns_ui_friendly_dictionary(self) -> None:
        result = SimpleNamespace(
            case_id=CASE_ID,
            record_count=4,
            finding_count=1,
            alert_count=1,
            incident_count=1,
            findings=(self.finding,),
            alerts=(self.alert,),
            incidents=(self.incident,),
        )
        service = Mock()
        service.analyze.return_value = result
        controller = AnalysisController(
            self.case_controller,
            service=service,
            pipeline=Mock(),
        )

        output = controller.analyze()

        service.analyze.assert_called_once_with(
            case_id=CASE_ID,
            records=None,
            timeline=None,
        )
        self.assertEqual(output["finding_count"], 1)
        self.assertEqual(output["incidents"][0]["incident_id"], "INC-001")

    def test_refresh_loads_all_sections_and_timeline(self) -> None:
        service = Mock()
        service.load_findings.return_value = (self.finding,)
        service.load_alerts.return_value = (self.alert,)
        service.load_incidents.return_value = (self.incident,)
        pipeline = Mock()
        pipeline.load_timeline.return_value = (self.timeline,)
        controller = AnalysisController(
            self.case_controller,
            service=service,
            pipeline=pipeline,
        )

        output = controller.refresh()

        self.assertEqual(output["findings"][0]["finding_id"], "FIND-001")
        self.assertEqual(output["alerts"][0]["alert_id"], "ALERT-001")
        self.assertEqual(output["timeline"][0]["timeline_event_id"], "TL-001")

    def test_refresh_allows_missing_timeline(self) -> None:
        service = Mock()
        service.load_findings.return_value = ()
        service.load_alerts.return_value = ()
        service.load_incidents.return_value = ()
        pipeline = Mock()
        pipeline.load_timeline.side_effect = ProcessingError("missing")
        controller = AnalysisController(
            self.case_controller,
            service=service,
            pipeline=pipeline,
        )

        output = controller.refresh()

        self.assertEqual(output["timeline"], [])

    def test_set_incident_status_keeps_human_decision_fields(self) -> None:
        service = Mock()
        service.set_incident_status.return_value = self.incident
        controller = AnalysisController(
            self.case_controller,
            service=service,
            pipeline=Mock(),
        )

        result = controller.set_incident_status(
            "INC-001",
            "confirmed",
            conclusion="Đã xác nhận",
            cia_impacts=("integrity",),
        )

        service.set_incident_status.assert_called_once_with(
            CASE_ID,
            "INC-001",
            "confirmed",
            conclusion="Đã xác nhận",
            cia_impacts=("integrity",),
        )
        self.assertEqual(result["incident_id"], "INC-001")


class IntegrationControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_controller = CaseController(service=FakeCaseService())
        self.case_controller.select_case(CASE_ID)

    def test_process_returns_ui_friendly_summary(self) -> None:
        service = Mock()
        service.process_case.return_value = SimpleNamespace(
            case_id=CASE_ID,
            requested_tools=("hayabusa", "evtxecmd"),
            succeeded_tools=("evtxecmd",),
            skipped_tools=(),
            failed_tools=("hayabusa",),
            parsed_record_count=6,
            normalized_count=6,
            duplicate_count=0,
            timeline_count=6,
            records_path=Path("analysis/normalized/records.json"),
            timeline_path=Path("analysis/timeline.json"),
            warnings=("hayabusa failed",),
        )
        controller = IntegrationController(
            self.case_controller,
            service=service,
        )

        result = controller.process()

        service.process_case.assert_called_once_with(
            CASE_ID,
            tool_ids=None,
            continue_on_error=True,
        )
        self.assertEqual(result["normalized_count"], 6)
        self.assertEqual(result["succeeded_tools"], ["evtxecmd"])
        self.assertIsInstance(result["records_path"], str)

    def test_process_requires_selected_case(self) -> None:
        controller = IntegrationController(
            CaseController(service=FakeCaseService()),
            service=Mock(),
        )

        with self.assertRaises(CurrentCaseRequiredError):
            controller.process()


class ReportControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_controller = CaseController(service=FakeCaseService())
        self.case_controller.select_case(CASE_ID)

    def test_generate_serializes_paths_for_tkinter(self) -> None:
        service = Mock()
        service.generate.return_value = SimpleNamespace(
            case_id=CASE_ID,
            formats=("html", "json"),
            output_paths={
                "html": Path("reports/investigation_report.html"),
                "json": Path("reports/investigation_report.json"),
            },
        )
        controller = ReportController(
            self.case_controller,
            service=service,
        )

        result = controller.generate(("html", "json"))

        service.generate.assert_called_once_with(
            CASE_ID,
            formats=("html", "json"),
        )
        self.assertEqual(result["formats"], ["html", "json"])
        self.assertIsInstance(result["output_paths"]["html"], str)

    def test_generate_requires_selected_case(self) -> None:
        case_controller = CaseController(service=FakeCaseService())
        controller = ReportController(case_controller, service=Mock())

        with self.assertRaises(CurrentCaseRequiredError):
            controller.generate(("json",))


class ComponentHelperTests(unittest.TestCase):
    def test_normalize_cell_handles_project_values(self) -> None:
        with self.subTest("none"):
            self.assertEqual(normalize_cell(None), "")
        with self.subTest("list"):
            self.assertEqual(normalize_cell(["A", "B"]), "A, B")
        with self.subTest("dict"):
            self.assertEqual(normalize_cell({"b": 2, "a": 1}), '{"a": 1, "b": 2}')

    def test_split_values_supports_comma_and_semicolon(self) -> None:
        self.assertEqual(
            _split_values("alpha, beta; gamma ,,"),
            ("alpha", "beta", "gamma"),
        )

    def test_data_table_rejects_empty_columns_when_display_available(self) -> None:
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Không có display cho Tkinter: {exc}")
        self.addCleanup(root.destroy)
        root.withdraw()

        with self.assertRaisesRegex(ValueError, "ít nhất một cột"):
            DataTable(root, ())

    def test_all_required_tabs_are_importable(self) -> None:
        required = {
            CaseTab,
            CollectionTab,
            EvidenceTab,
            AnalysisTab,
            TimelineTab,
            AgentTab,
            ReportTab,
        }
        self.assertEqual(len(required), 7)


class TimelineFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = (
            {
                "timeline_event_id": "TL-001",
                "timestamp": "2026-07-30T10:00:00Z",
                "hostname": "WIN-LAB01",
                "user": "alice",
                "details": {
                    "event_id": 4625,
                    "source_ip": "10.10.10.50",
                    "destination_ip": "10.10.10.20",
                },
            },
            {
                "timeline_event_id": "TL-002",
                "timestamp": "2026-07-30T10:05:00Z",
                "hostname": "WIN-LAB02",
                "user": "bob",
                "details": {
                    "event_id": 4688,
                    "source_ip": "",
                    "destination_ip": "192.168.1.25",
                },
            },
            {
                "timeline_event_id": "TL-003",
                "timestamp": "2026-07-30T11:00:00Z",
                "hostname": "WIN-LAB01",
                "user": "Administrator",
                "details": {
                    "event_id": 4624,
                    "source_ip": "10.10.10.50",
                    "destination_ip": "10.10.10.20",
                },
            },
        )

    def test_combined_filters_use_and_semantics(self) -> None:
        criteria = TimelineFilter.from_text(
            start="2026-07-30T09:59:00Z",
            end="2026-07-30T10:30:00Z",
            event_id="4625, 4688",
            hostname="win-lab01",
            user="ALI",
            ip="10.10.10.50",
        )

        filtered = filter_timeline_events(self.events, criteria)

        self.assertEqual(
            [event["timeline_event_id"] for event in filtered],
            ["TL-001"],
        )

    def test_ip_matches_source_or_destination(self) -> None:
        criteria = TimelineFilter.from_text(ip="192.168.1.25")

        filtered = filter_timeline_events(self.events, criteria)

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["timeline_event_id"], "TL-002")

    def test_event_id_accepts_comma_and_semicolon_lists(self) -> None:
        criteria = TimelineFilter.from_text(event_id="4624; 4688")

        filtered = filter_timeline_events(self.events, criteria)

        self.assertEqual(
            {event["timeline_event_id"] for event in filtered},
            {"TL-002", "TL-003"},
        )

    def test_time_range_is_inclusive(self) -> None:
        criteria = TimelineFilter.from_text(
            start="2026-07-30T10:00:00Z",
            end="2026-07-30T10:05:00Z",
        )

        filtered = filter_timeline_events(self.events, criteria)

        self.assertEqual(len(filtered), 2)

    def test_rejects_invalid_filter_values(self) -> None:
        with self.subTest("bad event id"):
            with self.assertRaisesRegex(ValueError, "Event ID"):
                TimelineFilter.from_text(event_id="4625,abc")
        with self.subTest("negative event id"):
            with self.assertRaisesRegex(ValueError, "số âm"):
                TimelineFilter.from_text(event_id="-1")
        with self.subTest("bad timestamp"):
            with self.assertRaisesRegex(ValueError, "ISO-8601"):
                TimelineFilter.from_text(start="30/07/2026 10:00")
        with self.subTest("reverse range"):
            with self.assertRaisesRegex(ValueError, "bắt đầu"):
                TimelineFilter.from_text(
                    start="2026-07-30T11:00:00Z",
                    end="2026-07-30T10:00:00Z",
                )


class MainWindowEntryPointTests(unittest.TestCase):
    def test_run_dashboard_wraps_headless_tcl_error(self) -> None:
        with patch(
            "ui.main_window.tk.Tk",
            side_effect=tk.TclError("no display"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Không thể khởi tạo"):
                run_dashboard()

    def test_run_dashboard_starts_mainloop(self) -> None:
        root = Mock()
        with (
            patch("ui.main_window.tk.Tk", return_value=root),
            patch("ui.main_window.MainWindow") as window_class,
        ):
            result = run_dashboard("D:/tool", actor="analyst")

        window_class.assert_called_once_with(
            root,
            "D:/tool",
            actor="analyst",
        )
        root.mainloop.assert_called_once_with()
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
