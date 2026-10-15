from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from analysis.analysis_service import AnalysisService
from analysis.investigation.checklist import ChecklistService
from case_management.case_service import CaseService
from common.enums import IncidentStatus
from common.json_utils import write_json
from evidence.evidence_service import EvidenceService
from integrations.parsers.evtxecmd_parser import EvtxECmdParser
from integrations.parsers.hayabusa_parser import HayabusaParser
from processing.processing_pipeline import ProcessingPipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
SCENARIOS = FIXTURES / "scenarios"


def load_scenario(name: str) -> dict:
    return json.loads((SCENARIOS / f"{name}.json").read_text(encoding="utf-8"))


class ScenarioWorkflowTests(unittest.TestCase):
    def project(self) -> Path:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        root = Path(temporary_directory.name)
        shutil.copytree(PROJECT_ROOT / "config", root / "config")
        return root

    def run_scenario(self, scenario_name: str):
        scenario = load_scenario(scenario_name)
        root = self.project()
        case = CaseService(root, actor="integration-test").create_case(
            title=f"Synthetic scenario: {scenario_name}",
            target_hostname="WIN-LAB01",
            profile_id=scenario["profile_id"],
        )
        paths = CaseService(root).repository.paths(case.case_id)
        write_json(paths.raw / "Files" / "scenario_input.json", scenario)
        EvidenceService(root).preserve_case(case.case_id)
        processing = ProcessingPipeline(
            root,
            actor="integration-test",
        ).process(
            case_id=case.case_id,
            records=scenario["records"],
        )
        analysis = AnalysisService(
            root,
            actor="integration-test",
        ).analyze(case_id=case.case_id)
        return root, case, scenario, processing, analysis

    def test_four_demo_scenarios_reach_expected_incident(self) -> None:
        scenario_names = (
            "account_compromise",
            "endpoint_compromise",
            "log_tampering",
            "service_disruption",
        )
        for scenario_name in scenario_names:
            with self.subTest(scenario=scenario_name):
                (
                    root,
                    case,
                    scenario,
                    processing,
                    analysis,
                ) = self.run_scenario(scenario_name)

                self.assertEqual(
                    processing.normalized_count,
                    len(scenario["records"]),
                )
                self.assertEqual(
                    processing.timeline_count,
                    len(scenario["records"]),
                )
                rule_ids = {alert.rule_id for alert in analysis.alerts}
                self.assertTrue(set(scenario["expected_rule_ids"]).issubset(rule_ids))
                incident = next(
                    item
                    for item in analysis.incidents
                    if item.details.get("incident_type")
                    == scenario["expected_incident_type"]
                )
                self.assertIs(incident.status, IncidentStatus.SUSPECTED)
                self.assertEqual(incident.cia_impacts, ())
                self.assertTrue(incident.timeline_event_ids)

                checklist = ChecklistService(root)
                checklist.save(
                    case.case_id,
                    [
                        {**item, "done": True}
                        for item in checklist.load(case.case_id)["items"]
                    ],
                )
                confirmed = AnalysisService(
                    root,
                    actor="integration-test",
                ).set_incident_status(
                    case.case_id,
                    incident.incident_id,
                    IncidentStatus.CONFIRMED,
                    conclusion=("Xác nhận từ fixture tổng hợp trong integration test."),
                    cia_impacts=tuple(scenario["confirmation_cia_impacts"]),
                )
                self.assertIs(
                    confirmed.status,
                    IncidentStatus.CONFIRMED,
                )
                self.assertEqual(
                    {impact.value for impact in confirmed.cia_impacts},
                    set(scenario["confirmation_cia_impacts"]),
                )

    def test_scenario_fixtures_have_safe_portable_references(self) -> None:
        for path in sorted(SCENARIOS.glob("*.json")):
            with self.subTest(fixture=path.name):
                scenario = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(scenario["schema_version"], 1)
                self.assertTrue(scenario["records"])
                record_ids = [record["record_id"] for record in scenario["records"]]
                self.assertEqual(len(record_ids), len(set(record_ids)))
                for record in scenario["records"]:
                    self.assertNotIn("case_id", record)
                    reference = PurePosixPath(record["raw_reference"])
                    self.assertFalse(reference.is_absolute())
                    self.assertNotIn("..", reference.parts)

    def test_evtxecmd_csv_flows_through_processing_and_detection(self) -> None:
        root = self.project()
        case = CaseService(root, actor="integration-test").create_case(
            title="EvtxECmd parser workflow",
            target_hostname="WIN-LAB01",
            profile_id="account_compromise",
        )
        records = EvtxECmdParser().parse(
            FIXTURES / "tool_outputs" / "evtxecmd_account_compromise.csv",
            case_id=case.case_id,
            hostname="WIN-LAB01",
            raw_reference=("analysis/tool_outputs/evtxecmd/account_compromise.csv"),
        )

        paths = CaseService(root).repository.paths(case.case_id)
        shutil.copy2(
            FIXTURES / "tool_outputs" / "evtxecmd_account_compromise.csv",
            paths.raw / "Files" / "evtxecmd_account_compromise.csv",
        )
        EvidenceService(root).preserve_case(case.case_id)
        ProcessingPipeline(root).process(
            case_id=case.case_id,
            records=records,
        )
        result = AnalysisService(root).analyze(case_id=case.case_id)

        self.assertEqual(len(records), 6)
        self.assertIn(
            "failed_logon_burst",
            {alert.rule_id for alert in result.alerts},
        )
        self.assertIn(
            "successful_logon_after_failures",
            {alert.rule_id for alert in result.alerts},
        )
        self.assertIn(
            "account_compromise",
            {incident.details.get("incident_type") for incident in result.incidents},
        )

    def test_hayabusa_csv_preserves_multiple_detection_contexts(self) -> None:
        records = HayabusaParser().parse(
            FIXTURES / "tool_outputs" / "hayabusa_endpoint.csv",
            case_id="CASE-20260729-999",
            hostname="WIN-LAB01",
            raw_reference="analysis/tool_outputs/hayabusa/timeline.csv",
        )

        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].process_name, "powershell.exe")
        self.assertEqual(records[0].event_id, 4688)
        self.assertEqual(records[1].event_id, 1102)
        self.assertEqual(records[1].user, "labadmin")


if __name__ == "__main__":
    unittest.main()
