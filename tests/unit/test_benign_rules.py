"""Negative fixtures: legitimate admin activity must not become an incident."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from analysis.detection import RuleEngine
from case_management.case_service import CaseService
from common.enums import ArtifactType
from models.normalized_record import NormalizedRecord

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class BenignRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(PROJECT_ROOT / "config", self.temp_path / "config")
        self.case = CaseService(self.temp_path).create_case(
            title="Benign controls",
            target_hostname="WIN-LAB01",
        )
        self.engine = RuleEngine(self.temp_path)

    def record(self, **overrides) -> NormalizedRecord:
        values = {
            "case_id": self.case.case_id,
            "source_type": "evtxecmd_event",
            "artifact_type": ArtifactType.EVENT_LOGS,
            "timestamp": datetime(2026, 7, 29, 8, tzinfo=timezone.utc),
            "summary": "benign",
            "hostname": "WIN-LAB01",
            "raw_reference": "analysis/tool_outputs/source.csv",
        }
        values.update(overrides)
        return NormalizedRecord(**values)

    def test_three_local_failures_are_below_burst_threshold(self) -> None:
        records = tuple(
            self.record(
                event_id=4625,
                record_id=f"REC-FORGET-{index}",
                timestamp=datetime(2026, 7, 29, 8, index, tzinfo=timezone.utc),
                user="labuser",
                source_ip="192.168.56.10",
                attributes={
                    "TargetUserName": "labuser",
                    "IpAddress": "192.168.56.10",
                    "LogonType": 2,
                },
            )
            for index in range(3)
        )
        self.assertEqual(
            self.engine.get("failed_logon_burst").evaluate(records),
            (),
        )

    def test_plain_powershell_without_indicators_is_quiet(self) -> None:
        record = self.record(
            artifact_type=ArtifactType.PROCESSES,
            source_type="live_process",
            record_id="REC-PS-ADMIN",
            process_name="powershell.exe",
            summary="powershell.exe -File C:\\Admin\\backup.ps1",
            attributes={"CommandLine": "powershell.exe -File C:\\Admin\\backup.ps1"},
        )
        self.assertEqual(
            self.engine.get("suspicious_powershell").evaluate((record,)),
            (),
        )

    def test_microsoft_scheduled_task_is_ignored(self) -> None:
        record = self.record(
            artifact_type=ArtifactType.SCHEDULED_TASKS,
            source_type="scheduled_task",
            record_id="REC-MS-TASK",
            event_id=4698,
            summary=r"Task created \\Microsoft\\Windows\\UpdateOrchestrator\\Backup",
            attributes={
                "TaskName": r"\Microsoft\Windows\UpdateOrchestrator\Backup",
                "Action": r"C:\Windows\System32\svchost.exe",
            },
        )
        self.assertEqual(
            self.engine.get("scheduled_task_created").evaluate((record,)),
            (),
        )

    def test_approved_service_stop_is_quiet(self) -> None:
        record = self.record(
            event_id=7036,
            record_id="REC-APPROVED-STOP",
            summary="PrintSpooler entered the stopped state",
            attributes={
                "ServiceName": "PrintSpooler",
                "State": "stopped",
                "change_approved": "true",
            },
        )
        self.assertEqual(
            self.engine.get("service_stopped").evaluate((record,)),
            (),
        )
