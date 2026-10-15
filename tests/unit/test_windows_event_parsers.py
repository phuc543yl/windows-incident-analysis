"""Production-shaped Windows tool rows, including nested data and provenance."""

from __future__ import annotations

import csv
import json
from dataclasses import replace
from datetime import timedelta

import pytest

from analysis.detection import RuleEngine
from analysis.detection.event_identity import group_windows_events
from analysis.helpers import integer_attribute, source_ip, target_user
from integrations.parsers import EvtxECmdParser, HayabusaParser
from integrations.parsers.base_parser import RowView
from processing.timeline_builder import TimelineBuilder
from ui.tabs.timeline_tab import TimelineTab
from ui.timeline_filter import TimelineFilter, filter_timeline_events

CASE_ID = "CASE-20261005-001"
SOURCE = r"D:\tool\tool\tool\runtime\cases\CASE-20261005-001\acquisition\raw\EventLogs\Security.evtx"


def native_logon(
    event_id=4625, native_id=100, timestamp="2026-10-05T15:13:10.3321234Z"
):
    data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "WIN8$",
        "SubjectDomainName": "WORKGROUP",
        "TargetUserName": "phuc",
        "TargetDomainName": "WIN8",
        "LogonType": "10",
        "ProcessId": "0x6e4",
        "ProcessName": r"C:\Windows\System32\svchost.exe",
        "IpAddress": "192.168.56.101",
        "Status": "0xc000006d",
        "SubStatus": "0xc000006a",
    }
    return {
        "RecordNumber": 200,
        "EventRecordId": native_id,
        "TimeCreated": timestamp,
        "EventId": event_id,
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "win8",
        "ProcessId": 808,
        "UserId": "S-1-5-18",
        "MapDescription": "",
        "UserName": r"WORKGROUP\WIN8$",
        "RemoteHost": "",
        "SourceFile": SOURCE,
        "Payload": json.dumps(
            {
                "EventData": {
                    "Data": [
                        {"@Name": name, "#text": value} for name, value in data.items()
                    ]
                }
            }
        ),
    }


def hayabusa_logon(
    event_id=4625, native_id=100, title="Logon Failure (Wrong Password)"
):
    return {
        "Timestamp": "2026-10-05 15:13:10.332 +00:00",
        "Computer": "win8",
        "Channel": "Sec",
        "EventID": event_id,
        "RecordID": native_id,
        "RuleTitle": title,
        "Details": "Type: 10 ¦ TgtUser: phuc ¦ SrcIP: 192.168.56.101 ¦ Proc: C:\\Windows\\System32\\svchost.exe ¦ PID: 0x6e4",
        "ExtraFieldInfo": "TargetDomainName: WIN8 ¦ Status: 0xc000006d ¦ SubStatus: 0xc000006a",
        "EvtxFile": SOURCE.replace("\\", "/"),
    }


def parse_row(parser, row, reference="analysis/tool_outputs/run/output.csv"):
    return parser.parse_row(
        RowView(row), case_id=CASE_ID, hostname="win8", raw_reference=reference
    )


def test_evtxecmd_csv_reads_named_payload_and_preserves_original_columns(tmp_path):
    row = native_logon()
    path = tmp_path / "evtxecmd.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    record = EvtxECmdParser().parse(path, case_id=CASE_ID)[0]
    assert record.user == r"WIN8\phuc"
    assert record.source_ip == "192.168.56.101"
    assert record.process_id == 1764  # EventData.ProcessId, not System.ProcessId.
    assert record.process_name.endswith("svchost.exe")
    assert integer_attribute(record, "LogonType") == 10
    assert target_user(record) == record.user
    assert source_ip(record) == record.source_ip
    assert record.attributes["SubjectUserName"] == "WIN8$"
    assert record.attributes["event_record_id"] == 100
    assert record.attributes["source_event_file"] == SOURCE
    assert "Đăng nhập thất bại" in record.summary
    assert "WIN8\\phuc" in record.summary
    assert "EventData" not in record.summary
    for name, value in row.items():
        assert record.attributes[name] == str(value)


@pytest.mark.parametrize("structured", [False, True])
def test_hayabusa_details_and_extra_info_fill_timeline_filters(tmp_path, structured):
    row = hayabusa_logon()
    if structured:
        row["Details"] = {
            "Type": 10,
            "TgtUser": "phuc",
            "SrcIP": "192.168.56.101",
            "PID": "0x6e4",
        }
        row["ExtraFieldInfo"] = {"TargetDomainName": "WIN8"}
        path = tmp_path / "hayabusa.jsonl"
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    else:
        path = tmp_path / "hayabusa.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(row))
            writer.writeheader()
            writer.writerow(row)
    record = HayabusaParser().parse(path, case_id=CASE_ID)[0]
    assert record.user == r"WIN8\phuc"
    assert record.source_ip == "192.168.56.101"
    assert integer_attribute(record, "LogonType") == 10
    assert record.process_id == 1764
    assert record.attributes["Details"] == row["Details"]
    assert record.attributes["channel"] == "Security"
    assert record.attributes["event_record_id"] == 100
    event = TimelineBuilder().build((record,))[0].to_dict()
    filtered = filter_timeline_events(
        (event,),
        TimelineFilter.from_text(user="phuc", ip="192.168.56.101", event_id="4625"),
    )
    assert len(filtered) == 1
    displayed = TimelineTab._display_row(filtered[0])
    assert displayed["source"] == "Hayabusa"
    assert displayed["ip"] == "192.168.56.101"


def test_subject_and_remote_hostname_are_not_invented_as_logon_target_or_ip():
    row = native_logon()
    payload = {
        "EventData": {
            "Data": [
                {"@name": "SubjectUserName", "#text": "SYSTEM"},
                {"@name": "IpAddress", "#text": "-"},
            ]
        }
    }
    row.update(
        Payload=payload, UserName="", RemoteHost="client.example", TargetUserName="-"
    )
    record = parse_row(EvtxECmdParser(), row)
    assert record.user == target_user(record) == ""
    assert record.source_ip == source_ip(record) == ""
    assert record.attributes["Payload"] == payload
    assert "SYSTEM" not in record.summary


@pytest.mark.parametrize("address", ["-", "n/a", "client.example", "999.1.2.3"])
def test_hayabusa_placeholder_fields_do_not_become_entities(address):
    row = hayabusa_logon()
    row["Details"] = f"Type: n/a ¦ TgtUser: - ¦ SrcIP: {address}"
    record = parse_row(HayabusaParser(), row)
    assert target_user(record) == ""
    assert source_ip(record) == ""
    assert integer_attribute(record, "LogonType") is None


def test_ipv6_and_windows_command_colons_are_preserved(tmp_path):
    row = {
        "Timestamp": "2026-10-05T15:13:10Z",
        "EventID": 4688,
        "RuleTitle": "Proc Exec",
        "Details": r"User: WIN8\phuc ¦ Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ¦ PID: 0x6e4 ¦ SrcIP: 2001:db8::1 ¦ CmdLine: powershell.exe -enc AAA | Write-Output C:\Temp\a.txt",
    }
    record = parse_row(HayabusaParser(), row)
    assert record.process_id == 1764
    assert record.process_name.endswith("powershell.exe")
    assert record.source_ip == "2001:db8::1"
    assert record.attributes["command_line"].endswith(r"| Write-Output C:\Temp\a.txt")
    row = native_logon(event_id=4688)
    command = "powershell.exe -enc AAA\nWrite-Output 'hello'"
    row["Payload"] = json.dumps(
        {
            "EventData": {
                "Data": [
                    {"@Name": "NewProcessId", "#text": "0x123"},
                    {"@Name": "NewProcessName", "#text": r"C:\Windows\powershell.exe"},
                    {"@Name": "CommandLine", "#text": command},
                ]
            }
        },
        indent=2,
    )
    path = tmp_path / "multiline.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    record = EvtxECmdParser().parse(path, case_id=CASE_ID)[0]
    assert record.attributes["Payload"] == row["Payload"]
    assert record.attributes["command_line"] == command
    assert record.process_id == 291
    assert record.process_name == r"C:\Windows\powershell.exe"


def test_evtxecmd_readable_description_and_user_data_are_retained():
    row = native_logon(event_id=1102)
    row["MapDescription"] = "The audit log was cleared"
    row["Payload"] = {"UserData": {"LogFileCleared": {"SubjectUserName": "phuc"}}}
    row["UserName"] = ""
    record = parse_row(EvtxECmdParser(), row)
    assert record.summary == "The audit log was cleared"
    assert record.user == "phuc"
    assert record.attributes["SubjectUserName"] == "phuc"


def native_representations(count, event_id=4625):
    records = []
    for index in range(count):
        timestamp = f"2026-10-05T15:13:{10 + index:02}.3321234Z"
        records.append(
            parse_row(
                EvtxECmdParser(),
                native_logon(event_id, 100 + index, timestamp),
                "analysis/tool_outputs/evtxecmd/run/evtxecmd.csv",
            )
        )
        for title in ("Logon Failure (Wrong Password)", "PW Guessing"):
            row = hayabusa_logon(event_id, 100 + index, title)
            row["Timestamp"] = f"2026-10-05 15:13:{10 + index:02}.332 +00:00"
            records.append(
                parse_row(
                    HayabusaParser(),
                    row,
                    "analysis/tool_outputs/hayabusa/run/hayabusa.csv",
                )
            )
    return tuple(records)


@pytest.mark.parametrize("count", [2, 5])
def test_failed_logon_threshold_counts_native_events_and_keeps_source_links(count):
    records = native_representations(count)
    rule = RuleEngine().get("failed_logon_burst")
    alerts = rule.evaluate(records)
    assert len(alerts) == (1 if count == 5 else 0)
    if alerts:
        assert alerts[0].details["failure_count"] == count
        assert alerts[0].details["source_record_count"] == count * 3
        assert set(alerts[0].source_record_ids) == {
            record.record_id for record in records
        }
        assert alerts[0].risk_score == rule.evaluate(records[::3])[0].risk_score


@pytest.mark.parametrize("count", [2, 5])
def test_success_after_failures_is_not_inflated_or_duplicated_by_tools(count):
    failures = native_representations(count)
    success_rows = native_representations(1, event_id=4624)
    successes = tuple(
        replace(record, timestamp=record.timestamp + timedelta(minutes=1))
        for record in success_rows
    )
    alerts = (
        RuleEngine()
        .get("successful_logon_after_failures")
        .evaluate((*failures, *successes))
    )
    assert len(alerts) == (1 if count == 5 else 0)
    if alerts:
        assert alerts[0].details["failure_count"] == count
        assert alerts[0].details["source_record_count"] == count * 3 + 3
        assert set(alerts[0].source_record_ids) == {
            record.record_id for record in (*failures, *successes)
        }


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_record_id", None),
        ("event_record_id", 0),
        ("event_record_id", 101),
        ("channel", "System"),
        ("source_event_file", ""),
        ("source_event_file", r"D:\other\Security.evtx"),
    ],
)
def test_native_identity_is_required_before_merging_timestamp_matches(field, value):
    first, second, _ = native_representations(1)
    second.attributes[field] = value
    if field == "event_record_id" and value is None:
        second.attributes.pop("RecordID")
    if field == "source_event_file" and value == "":
        second.attributes.pop("EvtxFile")
    assert len(group_windows_events((first, second))) == 2


def test_different_hosts_and_times_are_not_merged_even_with_reused_native_id():
    first, second, _ = native_representations(1)
    assert len(group_windows_events((first, replace(second, hostname="win9")))) == 2
    assert (
        len(
            group_windows_events(
                (
                    first,
                    replace(second, timestamp=second.timestamp + timedelta(seconds=1)),
                )
            )
        )
        == 2
    )


def test_success_uses_native_precision_and_links_partial_tool_representations():
    failures = native_representations(5)[::3]
    rows = native_representations(1, event_id=4624)
    success_time = failures[-1].timestamp + timedelta(microseconds=50)
    successes = tuple(
        replace(
            record,
            timestamp=success_time
            if index == 0
            else success_time.replace(microsecond=332000),
        )
        for index, record in enumerate(rows)
    )
    successes[-1].attributes.pop("logon_type")
    successes[-1].attributes.pop("Type")
    rule = RuleEngine().get("successful_logon_after_failures")
    alerts = rule.evaluate((*failures, *successes))
    assert len(alerts) == 1
    assert alerts[0].details["failure_count"] == 5
    assert set(alerts[0].source_record_ids) == {
        record.record_id for record in (*failures, *successes)
    }


def test_logon_rules_do_not_correlate_missing_account_and_ip_context():
    failure = parse_row(EvtxECmdParser(), native_logon())
    failure.user = failure.source_ip = ""
    failure.attributes.update(target_user="", source_ip="")
    failures = tuple(
        replace(
            failure,
            record_id=f"REC-{index}",
            attributes={**failure.attributes, "event_record_id": 100 + index},
        )
        for index in range(5)
    )
    success = replace(
        failure, event_id=4624, timestamp=failure.timestamp + timedelta(minutes=1)
    )
    assert RuleEngine().get("failed_logon_burst").evaluate(failures) == ()
    assert (
        RuleEngine()
        .get("successful_logon_after_failures")
        .evaluate((*failures, success))
        == ()
    )
