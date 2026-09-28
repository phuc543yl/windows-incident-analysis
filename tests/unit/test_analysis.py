from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_service import CaseService
from common.enums import (
    ArtifactType,
    CIAImpact,
    FindingSeverity,
    IncidentStatus,
)
from common.exceptions import AnalysisError, CaseClosedError
from common.json_utils import read_json_object, write_json
from models.normalized_record import NormalizedRecord
from processing.processing_pipeline import ProcessingPipeline
from processing.timeline_builder import TimelineBuilder
from analysis.analysis_service import AnalysisService
from analysis.history_service import AnalysisHistoryService
from analysis.analyzers import (
    DEFAULT_ANALYZERS,
    EventAnalyzer,
    ExecutionAnalyzer,
    NetworkAnalyzer,
    ProcessAnalyzer,
    RegistryAnalyzer,
    ServiceAnalyzer,
)
from analysis.correlation import CorrelationEngine
from analysis.detection import MitreMapper, RiskEngine, RuleEngine

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class AnalysisTestCase(unittest.TestCase):
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
            title="Analysis test",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )
        self.paths = self.service.repository.paths(self.case.case_id)

    def record(
        self,
        *,
        minute: int = 0,
        artifact_type: ArtifactType = ArtifactType.EVENT_LOGS,
        source_type: str = "evtxecmd_event",
        summary: str = "Windows event",
        event_id: int | None = None,
        record_id: str | None = None,
        case_id: str | None = None,
        **overrides,
    ) -> NormalizedRecord:
        arguments = {
            "case_id": case_id or self.case.case_id,
            "source_type": source_type,
            "artifact_type": artifact_type,
            "timestamp": datetime(
                2026,
                7,
                29,
                8,
                minute,
                tzinfo=timezone.utc,
            ),
            "summary": summary,
            "event_id": event_id,
            "hostname": "WIN-LAB01",
            "raw_reference": "analysis/tool_outputs/source.csv",
        }
        if record_id is not None:
            arguments["record_id"] = record_id
        arguments.update(overrides)
        return NormalizedRecord(**arguments)

    def incident_records(self) -> tuple[NormalizedRecord, ...]:
        failures = tuple(
            self.record(
                minute=index,
                event_id=4625,
                record_id=f"REC-FAIL-{index}",
                summary="RDP logon failed",
                user="alice",
                source_ip="203.0.113.10",
                attributes={
                    "TargetUserName": "alice",
                    "IpAddress": "203.0.113.10",
                    "LogonType": 10,
                },
            )
            for index in range(5)
        )
        success = self.record(
            minute=5,
            event_id=4624,
            record_id="REC-SUCCESS",
            summary="RDP logon succeeded",
            user="alice",
            source_ip="203.0.113.10",
            attributes={
                "TargetUserName": "alice",
                "IpAddress": "203.0.113.10",
                "LogonType": 10,
            },
        )
        powershell = self.record(
            minute=6,
            artifact_type=ArtifactType.PROCESSES,
            source_type="live_process",
            record_id="REC-POWERSHELL",
            summary="powershell.exe -EncodedCommand SQBFAFgA",
            process_name="powershell.exe",
            process_id=1200,
            parent_process_id=800,
            attributes={
                "CommandLine": (
                    "powershell.exe -EncodedCommand SQBFAFgA"
                )
            },
        )
        autorun = self.record(
            minute=7,
            artifact_type=ArtifactType.REGISTRY,
            source_type="recmd_registry",
            record_id="REC-AUTORUN",
            summary="Registry Run value created",
            file_path=(
                r"HKCU\Software\Microsoft\Windows"
                r"\CurrentVersion\Run\Updater"
            ),
            attributes={"Data": r"C:\Temp\evil.exe"},
        )
        task = self.record(
            minute=8,
            artifact_type=ArtifactType.SCHEDULED_TASKS,
            source_type="scheduled_task",
            record_id="REC-TASK",
            event_id=4698,
            summary="Scheduled task executes powershell from temp",
            user="SYSTEM",
            attributes={
                "Action": r"powershell C:\Temp\payload.ps1",
                "TargetUserName": "SYSTEM",
            },
        )
        execution = self.record(
            minute=9,
            artifact_type=ArtifactType.PREFETCH,
            source_type="pecmd_prefetch",
            record_id="REC-EXECUTION",
            summary="EVIL.EXE executed",
            process_name="EVIL.EXE",
            file_path=r"C:\Users\Public\EVIL.EXE",
        )
        clear_log = self.record(
            minute=10,
            event_id=1102,
            record_id="REC-CLEAR-LOG",
            summary="The audit log was cleared",
            user="alice",
        )
        service_stop = self.record(
            minute=11,
            event_id=7036,
            record_id="REC-SERVICE-STOP",
            summary="ImportantService entered the stopped state",
            attributes={
                "ServiceName": "ImportantService",
                "State": "stopped",
            },
        )
        service_change = self.record(
            minute=12,
            event_id=7045,
            record_id="REC-SERVICE-CHANGE",
            summary="A service was installed from C:\\Temp\\svc.exe",
            attributes={
                "ServiceName": "ImportantService",
                "ImagePath": r"C:\Temp\svc.exe",
            },
        )
        return (
            *failures,
            success,
            powershell,
            autorun,
            task,
            execution,
            clear_log,
            service_stop,
            service_change,
        )


class AnalyzerTests(AnalysisTestCase):
    def test_event_analyzer_maps_relevant_event(self) -> None:
        record = self.record(
            event_id=1102,
            summary="Security log cleared",
            record_id="REC-EVENT",
        )

        findings = EventAnalyzer().analyze((record,))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertEqual(
            findings[0].source_record_ids,
            ("REC-EVENT",),
        )
        self.assertEqual(findings[0].details["event_id"], 1102)

    def test_event_analyzer_ignores_routine_high_volume_events(self) -> None:
        records = tuple(
            self.record(event_id=event_id, record_id=f"REC-{event_id}")
            for event_id in (4624, 4625, 4688, 4104, 7036)
        )

        self.assertEqual(EventAnalyzer().analyze(records), ())

    def test_process_analyzer_requires_command_indicator(self) -> None:
        benign = self.record(
            artifact_type=ArtifactType.PROCESSES,
            source_type="live_process",
            summary="powershell.exe",
            process_name="powershell.exe",
            record_id="REC-BENIGN-PS",
        )
        suspicious = self.record(
            artifact_type=ArtifactType.PROCESSES,
            source_type="live_process",
            summary="powershell.exe -enc AAA",
            process_name="powershell.exe",
            record_id="REC-BAD-PS",
        )

        findings = ProcessAnalyzer().analyze((benign, suspicious))

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].source_record_ids,
            ("REC-BAD-PS",),
        )
        self.assertIn("-enc", findings[0].details["indicator_hits"])

    def test_network_analyzer_ignores_private_and_marks_public_ip(self) -> None:
        private = self.record(
            artifact_type=ArtifactType.NETWORK,
            source_type="live_network",
            destination_ip="192.168.1.10",
            record_id="REC-PRIVATE",
        )
        public = self.record(
            artifact_type=ArtifactType.NETWORK,
            source_type="live_network",
            destination_ip="8.8.8.8",
            record_id="REC-PUBLIC",
        )

        findings = NetworkAnalyzer().analyze((private, public))

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].details["destination_ip"],
            "8.8.8.8",
        )

    def test_registry_execution_and_service_analyzers(self) -> None:
        records = self.incident_records()
        cases = (
            (
                RegistryAnalyzer(),
                next(
                    record
                    for record in records
                    if record.record_id == "REC-AUTORUN"
                ),
                "T1547.001",
            ),
            (
                ExecutionAnalyzer(),
                next(
                    record
                    for record in records
                    if record.record_id == "REC-EXECUTION"
                ),
                "T1204.002",
            ),
            (
                ServiceAnalyzer(),
                next(
                    record
                    for record in records
                    if record.record_id == "REC-SERVICE-STOP"
                ),
                "T1489",
            ),
        )
        for analyzer, record, technique in cases:
            with self.subTest(analyzer=analyzer.analyzer_id):
                findings = analyzer.analyze((record,))
                self.assertEqual(len(findings), 1)
                self.assertIn(
                    technique,
                    findings[0].mitre_techniques,
                )

    def test_default_analyzers_have_unique_ids_and_reject_mixed_cases(self) -> None:
        self.assertEqual(
            len({item.analyzer_id for item in DEFAULT_ANALYZERS}),
            6,
        )
        with self.assertRaisesRegex(AnalysisError, "nhiều Case"):
            EventAnalyzer().analyze(
                (
                    self.record(event_id=4625),
                    self.record(
                        event_id=4625,
                        case_id="CASE-20260729-999",
                    ),
                )
            )


class RiskAndMitreTests(AnalysisTestCase):
    def test_risk_engine_applies_severity_floor_and_caps_score(self) -> None:
        engine = RiskEngine()

        high = engine.calculate(
            20,
            FindingSeverity.HIGH,
            record_count=5,
            indicator_hits=2,
        )
        capped = engine.calculate(
            99,
            FindingSeverity.CRITICAL,
            record_count=10,
            indicator_hits=10,
        )

        self.assertEqual(high, 71.0)
        self.assertEqual(capped, 100.0)

    def test_risk_engine_rejects_invalid_input(self) -> None:
        engine = RiskEngine()
        cases = (
            ((True, "high"), TypeError),
            ((101, "high"), ValueError),
            ((50, "invalid"), ValueError),
        )
        for arguments, exception in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(exception):
                    engine.calculate(*arguments)

    def test_mitre_mapper_returns_expected_details(self) -> None:
        mapper = MitreMapper(self.temp_path)

        self.assertEqual(
            mapper.technique_ids("suspicious_powershell"),
            ("T1059.001",),
        )
        mapping = mapper.mappings_for("security_log_cleared")[0]
        self.assertEqual(
            mapping["technique_name"],
            "Clear Windows Event Logs",
        )

    def test_mitre_mapper_detects_rule_mapping_mismatch(self) -> None:
        mapper = MitreMapper(self.temp_path)

        with self.assertRaisesRegex(AnalysisError, "không khớp"):
            mapper.validate_rule(
                "suspicious_powershell",
                ("T0000",),
            )


class DetectionRuleTests(AnalysisTestCase):
    def test_rule_engine_loads_all_configured_rules(self) -> None:
        engine = RuleEngine(self.temp_path)

        self.assertEqual(len(engine.rules), 14)
        self.assertEqual(
            {rule.rule_id for rule in engine.rules},
            {
                "failed_logon_burst",
                "successful_logon_after_failures",
                "suspicious_powershell",
                "registry_autorun_change",
                "scheduled_task_created",
                "suspicious_file_execution",
                "security_log_cleared",
                "service_stopped",
                "service_configuration_changed",
                "connection_flood",
                "event_log_service_shutdown",
                "powershell_scriptblock_suspicious",
                "file_integrity_change",
                "service_probe_failed",
            },
        )

    def test_rule_engine_detects_all_configured_scenarios(self) -> None:
        records = self.incident_records()
        findings = tuple(
            finding
            for analyzer in DEFAULT_ANALYZERS
            for finding in analyzer.analyze(records)
        )

        alerts = RuleEngine(self.temp_path).evaluate(records, findings)

        self.assertEqual(
            {alert.rule_id for alert in alerts},
            {
                "failed_logon_burst",
                "successful_logon_after_failures",
                "suspicious_powershell",
                "registry_autorun_change",
                "scheduled_task_created",
                "suspicious_file_execution",
                "security_log_cleared",
                "service_stopped",
                "service_configuration_changed",
            },
        )
        self.assertTrue(
            all(alert.mitre_techniques for alert in alerts)
        )
        self.assertTrue(
            all("mitre_mapping" in alert.details for alert in alerts)
        )

    def test_failed_logon_rule_respects_threshold_and_window(self) -> None:
        engine = RuleEngine(self.temp_path)
        rule = engine.get("failed_logon_burst")
        four = tuple(
            self.record(
                minute=index,
                event_id=4625,
                source_ip="203.0.113.20",
                user="bob",
                attributes={
                    "TargetUserName": "bob",
                    "IpAddress": "203.0.113.20",
                },
            )
            for index in range(4)
        )
        spread = tuple(
            self.record(
                minute=index * 11,
                event_id=4625,
                source_ip="203.0.113.30",
                user="carol",
                attributes={
                    "TargetUserName": "carol",
                    "IpAddress": "203.0.113.30",
                },
            )
            for index in range(5)
        )

        self.assertEqual(rule.evaluate(four), ())
        self.assertEqual(rule.evaluate(spread), ())

    def test_failed_logon_rule_collapses_one_continuous_episode(self) -> None:
        records = tuple(
            self.record(
                minute=index,
                event_id=4625,
                record_id=f"REC-BURST-{index}",
                source_ip="203.0.113.40",
                user="dave",
                attributes={
                    "TargetUserName": "dave",
                    "IpAddress": "203.0.113.40",
                },
            )
            for index in range(20)
        )
        rule = RuleEngine(self.temp_path).get("failed_logon_burst")

        alerts = rule.evaluate(records)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].details["failure_count"], 20)

    def test_service_stopped_requires_stopped_state(self) -> None:
        running = self.record(
            event_id=7036,
            record_id="REC-SERVICE-RUNNING",
            summary="ImportantService entered the running state",
            attributes={
                "ServiceName": "ImportantService",
                "State": "running",
            },
        )
        rule = RuleEngine(self.temp_path).get("service_stopped")

        self.assertEqual(rule.evaluate((running,)), ())

    def test_connection_flood_requires_threshold_for_same_service(self) -> None:
        def records(count: int, source: str, prefix: str):
            return tuple(
                self.record(
                    minute=20,
                    artifact_type=ArtifactType.NETWORK,
                    source_type="live_network",
                    record_id=f"REC-{prefix}-{index}",
                    summary="Live TCP connection",
                    source_ip="192.168.56.20",
                    destination_ip=source,
                    attributes={
                        "protocol": "tcp",
                        "local_address": "192.168.56.20",
                        "local_port": 8080,
                        "remote_address": source,
                        "remote_port": 40000 + index,
                        "state": "SynReceived",
                    },
                )
                for index in range(count)
            )

        rule = RuleEngine(self.temp_path).get("connection_flood")
        below = records(99, "192.168.56.30", "BELOW")
        flood = records(100, "192.168.56.30", "FLOOD")
        distributed = (
            *records(60, "192.168.56.31", "SRC-A"),
            *records(60, "192.168.56.32", "SRC-B"),
        )

        self.assertEqual(rule.evaluate(below), ())
        self.assertEqual(rule.evaluate(distributed), ())
        alerts = rule.evaluate(flood)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].details["connection_count"], 100)
        self.assertEqual(alerts[0].details["source_ip"], "192.168.56.30")
        self.assertEqual(alerts[0].details["destination_port"], 8080)
        self.assertEqual(alerts[0].mitre_techniques, ("T1499.002",))

    def test_rule_engine_can_limit_rules_to_investigation_profile(self) -> None:
        alerts = RuleEngine(self.temp_path).evaluate(
            self.incident_records(),
            rule_ids=(
                "failed_logon_burst",
                "successful_logon_after_failures",
                "suspicious_powershell",
            ),
        )

        self.assertEqual(
            {alert.rule_id for alert in alerts},
            {
                "failed_logon_burst",
                "successful_logon_after_failures",
                "suspicious_powershell",
            },
        )

    def test_success_after_failures_requires_rdp_logon_type(self) -> None:
        records = list(self.incident_records()[:6])
        success = records[-1]
        success.attributes["LogonType"] = 3
        rule = RuleEngine(self.temp_path).get(
            "successful_logon_after_failures"
        )

        alerts = rule.evaluate(tuple(records))

        self.assertEqual(alerts, ())

    def test_suspicious_powershell_alert_is_stable_and_links_finding(self) -> None:
        record = next(
            item
            for item in self.incident_records()
            if item.record_id == "REC-POWERSHELL"
        )
        finding = ProcessAnalyzer().analyze((record,))[0]
        rule = RuleEngine(self.temp_path).get(
            "suspicious_powershell"
        )

        first = rule.evaluate((record,), (finding,))[0]
        second = rule.evaluate((record,), (finding,))[0]

        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual(first.finding_ids, (finding.finding_id,))
        self.assertGreaterEqual(first.risk_score, 80)

    def test_rule_engine_rejects_unknown_rule_configuration(self) -> None:
        config = read_json_object(
            self.temp_path / "config" / "detection_rules.json"
        )
        config["rules"][0]["id"] = "not_implemented"
        path = self.temp_path / "bad-rules.json"
        write_json(path, config)

        with self.assertRaisesRegex(AnalysisError, "Chưa triển khai"):
            RuleEngine(self.temp_path, config_path=path)


class CorrelationTests(AnalysisTestCase):
    def alerts_and_context(self):
        records = self.incident_records()
        timeline = TimelineBuilder().build(records)
        findings = tuple(
            finding
            for analyzer in DEFAULT_ANALYZERS
            for finding in analyzer.analyze(records)
        )
        alerts = RuleEngine(self.temp_path).evaluate(records, findings)
        return records, timeline, findings, alerts

    def test_correlation_creates_four_suspected_incident_types(self) -> None:
        _, timeline, findings, alerts = self.alerts_and_context()

        incidents = CorrelationEngine().correlate(
            alerts,
            findings=findings,
            timeline=timeline,
        )

        self.assertEqual(
            {item.details["incident_type"] for item in incidents},
            {
                "account_compromise",
                "endpoint_compromise",
                "log_tampering",
                "service_disruption",
            },
        )
        self.assertTrue(
            all(
                incident.status is IncidentStatus.SUSPECTED
                for incident in incidents
            )
        )
        self.assertTrue(
            all(not incident.cia_impacts for incident in incidents)
        )

    def test_incidents_link_alert_findings_and_timeline(self) -> None:
        _, timeline, findings, alerts = self.alerts_and_context()

        incidents = CorrelationEngine().correlate(
            alerts,
            findings=findings,
            timeline=timeline,
        )
        account = next(
            incident
            for incident in incidents
            if incident.details["incident_type"]
            == "account_compromise"
        )

        self.assertTrue(account.alert_ids)
        # Routine 4624/4625 records are intentionally kept in the timeline,
        # not expanded into one Finding per event.
        self.assertEqual(account.finding_ids, ())
        self.assertTrue(account.timeline_event_ids)
        known_timeline_ids = {
            event.timeline_event_id for event in timeline
        }
        self.assertTrue(
            set(account.timeline_event_ids).issubset(
                known_timeline_ids
            )
        )

    def test_correlation_is_deterministic_and_rejects_mixed_cases(self) -> None:
        _, timeline, findings, alerts = self.alerts_and_context()
        engine = CorrelationEngine()

        first = engine.correlate(
            alerts,
            findings=findings,
            timeline=timeline,
        )
        second = engine.correlate(
            alerts,
            findings=findings,
            timeline=timeline,
        )

        self.assertEqual(
            [item.incident_id for item in first],
            [item.incident_id for item in second],
        )
        foreign = alerts[0].from_dict(
            {
                **alerts[0].to_dict(),
                "case_id": "CASE-20260729-999",
            }
        )
        with self.assertRaisesRegex(AnalysisError, "nhiều Case"):
            engine.correlate((alerts[0], foreign))

    def test_connection_flood_correlates_to_suspected_dos(self) -> None:
        records = tuple(
            self.record(
                minute=20,
                artifact_type=ArtifactType.NETWORK,
                source_type="live_network",
                record_id=f"REC-DOS-{index}",
                summary="Live TCP connection",
                source_ip="192.168.56.20",
                destination_ip="192.168.56.30",
                attributes={
                    "protocol": "tcp",
                    "local_address": "192.168.56.20",
                    "local_port": 8080,
                    "remote_address": "192.168.56.30",
                    "remote_port": 45000 + index,
                    "state": "SynReceived",
                },
            )
            for index in range(100)
        )
        alert = RuleEngine(self.temp_path).get(
            "connection_flood"
        ).evaluate(records)[0]

        incidents = CorrelationEngine().correlate((alert,))

        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident.details["incident_type"], "dos_attack")
        self.assertEqual(incident.status, IncidentStatus.SUSPECTED)
        self.assertEqual(incident.cia_impacts, ())
        self.assertTrue(
            incident.details["availability_impact_requires_confirmation"]
        )


class AnalysisServiceTests(AnalysisTestCase):
    def test_service_uses_only_rules_selected_by_case_profile(self) -> None:
        account_case = self.service.create_case(
            title="Account profile analysis",
            target_hostname="WIN-LAB01",
            profile_id="account_compromise",
        )
        records = tuple(
            NormalizedRecord.from_dict(
                {
                    **record.to_dict(),
                    "case_id": account_case.case_id,
                }
            )
            for record in self.incident_records()
        )

        result = AnalysisService(self.temp_path).analyze(
            case_id=account_case.case_id,
            records=records,
            timeline=(),
            persist=False,
        )

        self.assertEqual(
            {alert.rule_id for alert in result.alerts},
            {
                "failed_logon_burst",
                "successful_logon_after_failures",
                "suspicious_powershell",
            },
        )
        self.assertEqual(
            {
                incident.details["incident_type"]
                for incident in result.incidents
            },
            {"account_compromise"},
        )

    def test_service_applies_profile_default_time_window(self) -> None:
        records = (
            self.record(
                event_id=1102,
                record_id="REC-OLD",
                timestamp=datetime(2026, 7, 27, 8, tzinfo=timezone.utc),
            ),
            self.record(
                event_id=1102,
                record_id="REC-RECENT",
                timestamp=datetime(2026, 7, 29, 8, tzinfo=timezone.utc),
            ),
        )

        result = AnalysisService(self.temp_path).analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=(),
            persist=False,
        )

        self.assertEqual(result.record_count, 1)
        self.assertEqual(
            result.findings[0].source_record_ids,
            ("REC-RECENT",),
        )

    def test_service_persists_and_loads_analysis_results(self) -> None:
        records = self.incident_records()
        timeline = TimelineBuilder().build(records)
        service = AnalysisService(
            self.temp_path,
            actor="analyst",
        )

        result = service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=timeline,
        )

        self.assertEqual(result.record_count, len(records))
        self.assertGreater(result.finding_count, 0)
        self.assertEqual(result.alert_count, 9)
        self.assertEqual(result.incident_count, 4)
        self.assertTrue(result.findings_path.is_file())
        self.assertTrue(result.alerts_path.is_file())
        self.assertTrue(result.incidents_path.is_file())
        self.assertEqual(
            len(service.load_findings(self.case.case_id)),
            result.finding_count,
        )
        self.assertEqual(
            len(service.load_alerts(self.case.case_id)),
            result.alert_count,
        )
        self.assertEqual(
            len(service.load_incidents(self.case.case_id)),
            result.incident_count,
        )
        actions = [
            entry["action"]
            for entry in AuditLogger(
                self.case.case_id,
                self.temp_path,
            ).read_entries()
        ]
        self.assertEqual(actions[-1], "analysis_completed")

    def test_reanalysis_versions_previous_results_before_overwrite(self) -> None:
        records = self.incident_records()
        timeline = TimelineBuilder().build(records)
        service = AnalysisService(self.temp_path, actor="analyst")

        first = service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=timeline,
        )
        self.assertIsNone(first.previous_version_path)
        service.set_incident_status(
            self.case.case_id,
            first.incidents[0].incident_id,
            IncidentStatus.FALSE_POSITIVE,
            conclusion="Đã xác minh là hoạt động hợp lệ.",
        )
        previous_incidents = read_json_object(self.paths.incidents_json)

        second = service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=timeline,
        )

        self.assertIsNotNone(second.previous_version_path)
        version_path = second.previous_version_path
        self.assertTrue(version_path.is_dir())
        self.assertEqual(
            read_json_object(version_path / "incidents.json"),
            previous_incidents,
        )
        self.assertTrue((version_path / "findings.json").is_file())
        self.assertTrue((version_path / "alerts.json").is_file())
        metadata = read_json_object(version_path / "version.json")
        self.assertEqual(metadata["case_id"], self.case.case_id)
        self.assertEqual(metadata["archived_by"], "analyst")
        self.assertEqual(
            set(metadata["files"]),
            {"findings.json", "alerts.json", "incidents.json"},
        )
        versions = AnalysisHistoryService(
            self.temp_path
        ).list_versions(self.case.case_id)
        self.assertEqual(versions, (version_path,))
        actions = [
            entry["action"]
            for entry in AuditLogger(
                self.case.case_id,
                self.temp_path,
            ).read_entries()
        ]
        self.assertIn("analysis_results_archived", actions)
        self.assertEqual(actions[-1], "analysis_completed")

    def test_non_persistent_analysis_does_not_create_history(self) -> None:
        records = self.incident_records()
        timeline = TimelineBuilder().build(records)
        service = AnalysisService(self.temp_path)
        service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=timeline,
        )

        service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=timeline,
            persist=False,
        )

        self.assertEqual(
            AnalysisHistoryService(self.temp_path).list_versions(
                self.case.case_id
            ),
            (),
        )

    def test_service_can_load_processing_output_automatically(self) -> None:
        records = self.incident_records()
        ProcessingPipeline(self.temp_path).process(
            case_id=self.case.case_id,
            records=records,
        )

        result = AnalysisService(self.temp_path).analyze(
            case_id=self.case.case_id,
            persist=False,
        )

        self.assertEqual(result.record_count, len(records))
        self.assertEqual(result.alert_count, 9)
        self.assertIsNone(result.findings_path)

    def test_incident_confirmation_requires_conclusion_and_cia(self) -> None:
        records = self.incident_records()
        service = AnalysisService(self.temp_path)
        result = service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=TimelineBuilder().build(records),
        )
        incident = result.incidents[0]

        with self.assertRaisesRegex(AnalysisError, "kết luận"):
            service.set_incident_status(
                self.case.case_id,
                incident.incident_id,
                IncidentStatus.CONFIRMED,
                conclusion="",
                cia_impacts=(CIAImpact.CONFIDENTIALITY,),
            )
        with self.assertRaisesRegex(AnalysisError, "CIA"):
            service.set_incident_status(
                self.case.case_id,
                incident.incident_id,
                IncidentStatus.CONFIRMED,
                conclusion="Đã xác nhận.",
            )

        confirmed = service.set_incident_status(
            self.case.case_id,
            incident.incident_id,
            IncidentStatus.CONFIRMED,
            conclusion="Tài khoản đã bị sử dụng trái phép.",
            cia_impacts=(
                CIAImpact.CONFIDENTIALITY,
                CIAImpact.INTEGRITY,
            ),
        )

        self.assertEqual(
            confirmed.status,
            IncidentStatus.CONFIRMED,
        )
        self.assertEqual(
            confirmed.cia_impacts,
            (
                CIAImpact.CONFIDENTIALITY,
                CIAImpact.INTEGRITY,
            ),
        )
        reloaded = next(
            item
            for item in service.load_incidents(self.case.case_id)
            if item.incident_id == incident.incident_id
        )
        self.assertEqual(reloaded.status, IncidentStatus.CONFIRMED)

    def test_analyst_can_mark_false_positive_without_cia_impact(self) -> None:
        records = self.incident_records()
        service = AnalysisService(self.temp_path)
        incident = service.analyze(
            case_id=self.case.case_id,
            records=records,
            timeline=TimelineBuilder().build(records),
        ).incidents[0]

        updated = service.set_incident_status(
            self.case.case_id,
            incident.incident_id,
            IncidentStatus.FALSE_POSITIVE,
            conclusion="Hoạt động quản trị đã được phê duyệt.",
        )

        self.assertEqual(
            updated.status,
            IncidentStatus.FALSE_POSITIVE,
        )
        self.assertEqual(updated.cia_impacts, ())

    def test_service_rejects_case_mismatch_closed_case_and_bad_envelope(
        self,
    ) -> None:
        service = AnalysisService(self.temp_path)
        with self.assertRaisesRegex(AnalysisError, "khác Case"):
            service.analyze(
                case_id=self.case.case_id,
                records=(
                    self.record(case_id="CASE-20260729-999"),
                ),
                timeline=(),
            )

        write_json(
            self.paths.alerts_json,
            {
                "schema_version": 1,
                "case_id": self.case.case_id,
                "alert_count": 2,
                "alerts": [],
            },
        )
        with self.assertRaisesRegex(AnalysisError, "envelope"):
            service.load_alerts(self.case.case_id)

        self.service.close_case(self.case.case_id)
        with self.assertRaises(CaseClosedError):
            service.analyze(
                case_id=self.case.case_id,
                records=(),
                timeline=(),
            )


if __name__ == "__main__":
    unittest.main()
