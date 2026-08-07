from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from common.json_utils import read_json_object
from experiments.ground_truth import (
    GroundTruthResult,
    evaluate_scenario,
    run_ground_truth_suite,
    write_ground_truth_results,
)
from models.alert import Alert

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class GroundTruthExperimentTests(unittest.TestCase):
    def test_four_scenarios_match_declared_ground_truth(self) -> None:
        result = run_ground_truth_suite(PROJECT_ROOT)

        self.assertEqual(result.scenario_count, 4)
        self.assertEqual(result.passed_count, 4)
        self.assertEqual(result.failed_count, 0)
        self.assertTrue(result.passed)
        self.assertEqual(result.true_positive_rules, 4)
        self.assertEqual(result.false_positive_rules, 0)
        self.assertEqual(result.false_negative_rules, 0)
        self.assertEqual(result.precision, 1.0)
        self.assertEqual(result.recall, 1.0)
        self.assertEqual(result.f1_score, 1.0)
        self.assertGreater(result.total_input_size_bytes, 0)
        self.assertGreater(result.total_case_size_bytes, 0)
        self.assertGreater(result.mean_case_size_bytes, 0)
        self.assertGreater(result.mean_processing_seconds, 0)
        self.assertGreater(result.mean_analysis_seconds, 0)
        self.assertGreater(result.mean_total_seconds, 0)
        for item in result.results:
            self.assertGreater(item.input_size_bytes, 0)
            self.assertGreater(item.normalized_size_bytes, 0)
            self.assertGreater(item.timeline_size_bytes, 0)
            self.assertGreater(item.analysis_result_size_bytes, 0)
            self.assertGreater(item.case_size_bytes, 0)
            self.assertGreater(item.processing_seconds, 0)
            self.assertGreater(item.analysis_seconds, 0)
            self.assertAlmostEqual(
                item.total_seconds,
                item.processing_seconds + item.analysis_seconds,
            )
        self.assertEqual(
            {item.scenario_id for item in result.results},
            {
                "rdp_brute_force",
                "suspicious_powershell",
                "scheduled_task_persistence",
                "malicious_service",
            },
        )

    def test_result_writer_creates_json_and_excel_friendly_csv(self) -> None:
        result = run_ground_truth_suite(PROJECT_ROOT)
        with tempfile.TemporaryDirectory() as temp:
            json_path, csv_path = write_ground_truth_results(result, temp)

            data = read_json_object(json_path)
            csv_text = csv_path.read_text(encoding="utf-8-sig")

        self.assertEqual(data["scenario_count"], 4)
        self.assertTrue(data["passed"])
        self.assertIn("scenario_id,passed", csv_text)
        self.assertIn("rdp_brute_force", csv_text)
        self.assertIn("processing_seconds", csv_text)
        self.assertIn("case_size_bytes", csv_text)

    def test_evaluator_reports_false_positive_and_false_negative(self) -> None:
        scenario = {
            "scenario_id": "metric-test",
            "title": "Metric test",
            "records": [{"record_id": "REC-1"}],
            "ground_truth": {
                "expected_alert_count": 1,
                "expected_rule_ids": ["expected_rule"],
                "expected_mitre_techniques": ["T1111"],
            },
        }
        unexpected = Alert(
            case_id="CASE-20260730-001",
            rule_id="unexpected_rule",
            title="Unexpected",
            description="Synthetic metric test",
            severity="medium",
            risk_score=50,
            mitre_techniques=("T9999",),
        )

        result = evaluate_scenario(scenario, (unexpected,))

        self.assertIsInstance(result, GroundTruthResult)
        self.assertFalse(result.passed)
        self.assertEqual(result.false_positive_rules, ("unexpected_rule",))
        self.assertEqual(result.false_negative_rules, ("expected_rule",))
        self.assertEqual(result.missing_mitre_techniques, ("T1111",))
        self.assertEqual(result.precision, 0.0)
        self.assertEqual(result.recall, 0.0)


if __name__ == "__main__":
    unittest.main()
