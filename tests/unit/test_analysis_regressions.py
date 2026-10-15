"""Regression cases for evidence gates and misleading incident context."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from analysis.analysis_service import AnalysisService
from analysis.correlation.dos_attack import DosAttackCorrelation
from analysis.correlation.endpoint_compromise import EndpointCompromiseCorrelation
from analysis.correlation.log_tampering import LogTamperingCorrelation
from analysis.correlation.service_disruption import ServiceDisruptionCorrelation
from analysis.detection import RuleEngine
from analysis.investigation.baseline import BaselineComparer
from analysis.investigation.checklist import ChecklistService
from case_management.case_service import CaseService
from common.enums import ArtifactType
from common.exceptions import AnalysisError, IntegrityVerificationError, ProcessingError
from common.json_utils import read_json_object, write_json
from evidence.evidence_service import EvidenceService
from evidence.integrity_verifier import VERIFICATION_FILENAME
from models.alert import Alert
from models.normalized_record import NormalizedRecord
from processing.processing_pipeline import ProcessingPipeline
from ui.main_window import MainWindow

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WHEN = datetime(2026, 10, 7, 8, tzinfo=timezone.utc)


@pytest.fixture
def lab(tmp_path):
    shutil.copytree(PROJECT_ROOT / "config", tmp_path / "config")
    service = CaseService(tmp_path)
    case = service.create_case(
        title="Regression fixture",
        target_hostname="WIN-A",
        profile_id="general_investigation",
    )
    paths = service.repository.paths(case.case_id)
    (paths.raw / "EventLogs" / "Security.evtx").write_bytes(b"synthetic evidence")
    EvidenceService(tmp_path).preserve_case(case.case_id)
    return tmp_path, case, paths


def record(case, **values):
    defaults = dict(
        case_id=case.case_id,
        record_id="REC-CLEAR",
        timestamp=WHEN,
        source_type="evtxecmd_event",
        artifact_type=ArtifactType.EVENT_LOGS,
        event_id=1102,
        summary="The audit log was cleared",
        hostname="WIN-A",
        raw_reference="acquisition/raw/EventLogs/Security.evtx",
    )
    return NormalizedRecord(**{**defaults, **values})


def alert(rule_id, **details):
    return Alert(
        case_id="CASE-20261007-001",
        rule_id=rule_id,
        title=rule_id,
        description="Regression fixture",
        severity="high",
        risk_score=80,
        created_at=WHEN,
        details=details,
    )


def test_hash_failure_blocks_analysis_and_preserves_previous_results(lab):
    root, case, paths = lab
    ProcessingPipeline(root).process(case_id=case.case_id, records=(record(case),))
    service = AnalysisService(root)
    service.analyze(case_id=case.case_id)
    previous = paths.alerts_json.read_bytes()
    (paths.raw / "EventLogs" / "Security.evtx").write_bytes(b"altered evidence")
    messages = []
    with pytest.raises(IntegrityVerificationError):
        service.analyze(case_id=case.case_id, on_progress=messages.append)
    assert paths.alerts_json.read_bytes() == previous
    assert not tuple(paths.analysis_history.iterdir())
    assert read_json_object(paths.analysis / VERIFICATION_FILENAME)["success"] is False
    assert not any("Phân tích hoàn tất" in message for message in messages)


def test_missing_manifest_blocks_case_analysis_but_allows_memory_dry_run(lab):
    root, case, paths = lab
    paths.manifest_json.unlink()
    service = AnalysisService(root)
    with pytest.raises(IntegrityVerificationError):
        service.analyze(case_id=case.case_id, records=(record(case),))
    result = service.analyze(
        case_id=case.case_id, records=(record(case),), persist=False
    )
    assert result.alert_count == 1
    assert not paths.alerts_json.exists()


def test_explicit_hash_setting_is_respected_and_requires_boolean(lab):
    root, case, paths = lab
    pipeline = ProcessingPipeline(root)
    pipeline.process(case_id=case.case_id, records=(record(case),))
    settings_path = root / "config" / "settings.json"
    settings = read_json_object(settings_path)
    settings["case"]["verify_hash_before_analysis"] = False
    write_json(settings_path, settings)
    paths.manifest_json.unlink()
    assert (
        AnalysisService(root).analyze(case_id=case.case_id, persist=False).alert_count
        == 1
    )
    settings["case"]["verify_hash_before_analysis"] = "false"
    write_json(settings_path, settings)
    with pytest.raises(AnalysisError, match="boolean"):
        AnalysisService(root).analyze(case_id=case.case_id, persist=False)


def test_changed_normalized_records_are_rejected(lab):
    root, case, paths = lab
    processed = ProcessingPipeline(root).process(
        case_id=case.case_id, records=(record(case),)
    )
    data = read_json_object(processed.records_path)
    data["records"][0]["summary"] = "Changed normalized record"
    write_json(processed.records_path, data)
    with pytest.raises(ProcessingError, match="chuẩn hóa đã thay đổi"):
        AnalysisService(root).analyze(case_id=case.case_id)


def test_new_manifest_requires_reprocessing(lab):
    root, case, paths = lab
    pipeline = ProcessingPipeline(root)
    pipeline.process(case_id=case.case_id, records=(record(case),))
    (paths.raw / "EventLogs" / "Security.evtx").write_bytes(b"new acquisition")
    EvidenceService(root).preserve_case(case.case_id, rebuild=True)
    with pytest.raises(ProcessingError, match="manifest đã đổi"):
        AnalysisService(root).analyze(case_id=case.case_id)
    pipeline.process(case_id=case.case_id, records=(record(case),))
    assert AnalysisService(root).analyze(case_id=case.case_id).alert_count == 1


@pytest.mark.parametrize("event_id", [1, 4688])
def test_process_event_alone_does_not_identify_powershell(lab, event_id):
    root, case, _ = lab
    sample = record(
        case,
        event_id=event_id,
        process_name="cmd.exe",
        summary="cmd.exe /c echo -enc",
        attributes={"CommandLine": "cmd.exe /c echo -enc", "Comment": "powershell.exe"},
    )
    assert RuleEngine(root).get("suspicious_powershell").evaluate((sample,)) == ()


@pytest.mark.parametrize(
    "name,command",
    [
        (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -EncodedCommand AAA",
        ),
        ("cmd.exe", "cmd.exe /c powershell.exe -enc AAA"),
        ("", '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -enc AAA'),
    ],
)
def test_powershell_launch_context_is_recognized_without_duplicate_alias_hits(
    lab, name, command
):
    root, case, _ = lab
    sample = record(
        case, event_id=4688, process_name=name, attributes={"CommandLine": command}
    )
    alerts = RuleEngine(root).get("suspicious_powershell").evaluate((sample,))
    assert len(alerts) == 1
    assert len(alerts[0].details["indicator_hits"]) == 1
    assert alerts[0].details["high_risk_combo"] is False


@pytest.mark.parametrize(
    "attributes",
    [
        {"authorized": False},
        {"downtime_seconds": 120},
        {"authorized": False, "downtime_seconds": 59},
        {"authorized": False, "downtime_seconds": -1},
        {"authorized": True, "downtime_seconds": 120},
        {"maintenance": False, "downtime_seconds": 120},
    ],
)
def test_service_stop_needs_declared_context_and_minimum_downtime(lab, attributes):
    root, case, _ = lab
    sample = record(
        case,
        event_id=7036,
        summary="LabService stopped",
        attributes={
            "ServiceName": "LabService",
            "State": "stopped",
            **attributes,
        },
    )
    assert RuleEngine(root).get("service_stopped").evaluate((sample,)) == ()


def test_service_stop_with_evidence_is_alerted_and_running_state_is_not(lab):
    root, case, _ = lab
    sample = record(
        case,
        event_id=7036,
        summary="LabService stopped",
        attributes={
            "ServiceName": "LabService",
            "State": "stopped",
            "authorized": False,
            "downtime_seconds": 60,
        },
    )
    rule = RuleEngine(root).get("service_stopped")
    assert len(rule.evaluate((sample,))) == 1
    sample.attributes["State"] = "running"
    assert rule.evaluate((sample,)) == ()


def test_endpoint_correlation_rejects_unrelated_hosts_and_single_entity(lab):
    first = alert("suspicious_powershell", hostname="WIN-A", target_user="alice")
    second = alert(
        "scheduled_task_created",
        hostname="WIN-B",
        target_user="bob",
        file_path="C:/Other/other.ps1",
    )
    correlation = EndpointCompromiseCorrelation()
    assert correlation.correlate((first, second)) == ()
    second.details["hostname"] = "WIN-A"
    matches = correlation.correlate((first, second))
    assert len(matches) == 1
    assert matches[0].details["shared_entities"] == ("hostname:win-a",)


def test_missing_endpoint_context_does_not_correlate_by_time(lab):
    assert (
        EndpointCompromiseCorrelation().correlate(
            (
                alert("suspicious_powershell"),
                alert("scheduled_task_created"),
            )
        )
        == ()
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"hostname": "WIN-B"},
        {"destination_ip": "192.168.122.99"},
        {"destination_port": 443},
        {"protocol": "udp"},
    ],
)
def test_dos_probe_must_target_same_endpoint_and_port(lab, changes):
    context = dict(
        hostname="WIN-A",
        destination_ip="192.168.122.136",
        destination_port=8080,
        protocol="tcp",
    )
    flood = alert("connection_flood", **context)
    probe = alert("service_probe_failed", **{**context, **changes})
    match = DosAttackCorrelation().correlate((flood, probe))[0]
    assert match.details["probe_supported"] is False
    assert match.alerts == (flood,)


def test_probe_rule_exports_target_context_and_links_matching_flood(lab):
    root, case, _ = lab
    sample = record(
        case,
        artifact_type=ArtifactType.SERVICES,
        source_type="live_service",
        event_id=None,
        attributes={
            "ServiceName": "LabService",
            "probe_status": "timeout",
            "target_ip": "192.168.122.136",
            "port": 8080,
            "protocol": "tcp",
        },
    )
    probe = RuleEngine(root).get("service_probe_failed").evaluate((sample,))[0]
    flood = alert(
        "connection_flood",
        hostname="WIN-A",
        destination_ip="192.168.122.136",
        destination_port=8080,
        protocol="tcp",
    )
    flood.case_id = case.case_id
    assert (
        DosAttackCorrelation().correlate((flood, probe))[0].details["probe_supported"]
        is True
    )


def test_service_and_log_companions_do_not_cross_hosts(lab):
    stopped = alert("service_stopped", hostname="WIN-A", service_name="LabService")
    probe = alert("service_probe_failed", hostname="WIN-B", service_name="LabService")
    assert (
        not ServiceDisruptionCorrelation()
        .correlate((stopped, probe))[0]
        .details["probe_supported"]
    )
    cleared = alert("security_log_cleared", hostname="WIN-A")
    powershell = alert("suspicious_powershell", hostname="WIN-B")
    assert LogTamperingCorrelation().correlate((cleared, powershell))[0].alerts == (
        cleared,
    )


def test_timeline_persists_current_links_and_drops_previous_links(lab):
    root, case, _ = lab
    pipeline = ProcessingPipeline(root)
    pipeline.process(case_id=case.case_id, records=(record(case),))
    result = AnalysisService(root).analyze(case_id=case.case_id)
    timeline = pipeline.load_timeline(case.case_id)
    assert timeline[0].alert_ids == (result.alerts[0].alert_id,)
    assert timeline[0].finding_ids == (result.findings[0].finding_id,)
    benign = record(case, event_id=4624, summary="Routine logon")
    AnalysisService(root).analyze(
        case_id=case.case_id, records=(benign,), timeline=timeline
    )
    updated = pipeline.load_timeline(case.case_id)[0]
    assert updated.alert_ids == ()
    assert updated.finding_ids == ()
    assert timeline[0].alert_ids  # Linking does not mutate the supplied old timeline.


def test_confirmed_requires_saved_complete_profile_checklist(lab):
    root, case, _ = lab
    service = AnalysisService(root)
    incident = service.analyze(case_id=case.case_id, records=(record(case),)).incidents[
        0
    ]
    kwargs = dict(conclusion="Analyst verified evidence", cia_impacts=("integrity",))
    with pytest.raises(AnalysisError, match="checklist"):
        service.set_incident_status(
            case.case_id, incident.incident_id, "confirmed", **kwargs
        )
    checklist = ChecklistService(root)
    with pytest.raises(AnalysisError):
        checklist.save(case.case_id, [])
    items = [{**item, "done": True} for item in checklist.load(case.case_id)["items"]]
    with pytest.raises(AnalysisError, match="đầy đủ"):
        checklist.save(case.case_id, items[:-1])
    checklist.save(case.case_id, items)
    assert (
        service.set_incident_status(
            case.case_id, incident.incident_id, "confirmed", **kwargs
        ).status.value
        == "confirmed"
    )


def test_baseline_t0_retains_evidence_and_reports_t1_changes(lab):
    root, case, paths = lab
    pipeline = ProcessingPipeline(root)
    before = record(
        case,
        source_type="live_service",
        artifact_type=ArtifactType.SERVICES,
        event_id=None,
        attributes={
            "ServiceName": "LabService",
            "State": "Running",
            "StartMode": "Auto",
        },
    )
    pipeline.process(case_id=case.case_id, records=(before,))
    comparer = BaselineComparer(root)
    captured = comparer.capture(case.case_id)
    bundle = paths.root / captured["evidence_bundle"]
    assert bundle.is_file()
    assert (
        EvidenceService(root).inspect_bundle(
            bundle, expected_sha256=captured["evidence_bundle_sha256"]
        )["valid_zip"]
        is True
    )
    after = record(
        case,
        source_type="live_service",
        artifact_type=ArtifactType.SERVICES,
        event_id=None,
        timestamp=WHEN + timedelta(minutes=10),
        attributes={
            "ServiceName": "LabService",
            "State": "Stopped",
            "StartMode": "Disabled",
        },
    )
    diff = comparer.compare(case.case_id, (after,))
    assert any(
        change.category == "service" and "stopped" in change.after
        for change in diff.changes
    )
    assert comparer.latest(case.case_id)["states"] == captured["states"]
    second = comparer.capture(case.case_id)
    assert second["snapshot_id"] != captured["snapshot_id"]
    assert len(tuple((paths.analysis / "baselines").glob("*.json"))) == 2


def test_baseline_checksum_detects_changed_t0(lab):
    root, case, paths = lab
    ProcessingPipeline(root).process(case_id=case.case_id, records=(record(case),))
    comparer = BaselineComparer(root)
    captured = comparer.capture(case.case_id)
    snapshot = paths.analysis / "baselines" / f"{captured['snapshot_id']}.json"
    snapshot.write_text("{}", encoding="utf-8")
    with pytest.raises(AnalysisError, match="SHA-256"):
        comparer.compare(case.case_id)


def test_before_after_file_pairs_include_extension(lab):
    root, case, paths = lab
    files = paths.raw / "Files"
    for name, content in {
        "data_before.txt": "A",
        "data_after.txt": "B",
        "data_before.csv": "C",
        "data_after.csv": "C",
    }.items():
        (files / name).write_text(content, encoding="utf-8")
    changes = BaselineComparer(root).compare(case.case_id).changes
    assert [(change.category, change.identifier) for change in changes] == [
        ("file_hash", "data.txt")
    ]


def test_shared_file_with_unknown_anchor_does_not_merge_two_known_hosts(lab):
    common = "C:/Lab/shared.ps1"
    first = alert("suspicious_powershell", file_path=common)
    same_file_a = alert("scheduled_task_created", hostname="WIN-A", file_path=common)
    same_file_b = alert("registry_autorun_change", hostname="WIN-B", file_path=common)
    matches = EndpointCompromiseCorrelation().correlate(
        (first, same_file_a, same_file_b)
    )
    assert len(matches) == 1
    assert same_file_b not in matches[0].alerts


def test_rdp_success_does_not_use_failures_from_other_host(lab):
    root, case, _ = lab
    failures = tuple(
        record(
            case,
            record_id=f"REC-FAIL-{index}",
            event_id=4625,
            hostname="WIN-A",
            source_ip="192.168.122.130",
            user="alice",
            timestamp=WHEN + timedelta(minutes=index),
            attributes={
                "TargetUserName": "alice",
                "IpAddress": "192.168.122.130",
                "LogonType": 10,
            },
        )
        for index in range(5)
    )
    success = record(
        case,
        event_id=4624,
        hostname="WIN-B",
        source_ip="192.168.122.130",
        user="alice",
        timestamp=WHEN + timedelta(minutes=6),
        attributes={
            "TargetUserName": "alice",
            "IpAddress": "192.168.122.130",
            "LogonType": 10,
        },
    )
    rule = RuleEngine(root).get("successful_logon_after_failures")
    assert rule.evaluate((*failures, success)) == ()
    success.hostname = "WIN-A"
    assert len(rule.evaluate((*failures, success))) == 1


def test_overview_does_not_treat_manifest_as_successful_verification():
    assert "chưa có kết quả" in MainWindow._integrity_summary({}, has_manifest=True)
    assert "KHÔNG ĐẠT" in MainWindow._integrity_summary(
        {"success": False}, has_manifest=True
    )
    assert "gần nhất" in MainWindow._integrity_summary(
        {"success": True}, has_manifest=True
    )
