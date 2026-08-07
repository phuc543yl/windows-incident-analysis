from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_service import CaseService
from common.enums import ArtifactType
from common.exceptions import CaseClosedError, ProcessingError
from common.json_utils import read_json_object, write_json
from models.normalized_record import NormalizedRecord
from processing.deduplicator import RecordDeduplicator
from processing.live_record_loader import LiveRecordLoader
from processing.normalizer import RecordNormalizer
from processing.processing_pipeline import ProcessingPipeline
from processing.schema import (
    parse_records_envelope,
    parse_timeline_envelope,
    records_envelope,
    timeline_envelope,
)
from processing.timeline_builder import TimelineBuilder
from processing.timestamp_normalizer import TimestampNormalizer

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class ProcessingTestCase(unittest.TestCase):
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
            title="Processing test",
            target_hostname="WIN-LAB01",
            profile_id="general_investigation",
        )
        self.paths = self.service.repository.paths(self.case.case_id)

    def record(
        self,
        *,
        timestamp: str = "2026-07-29T10:00:00Z",
        artifact_type: ArtifactType = ArtifactType.EVENT_LOGS,
        source_type: str = "evtxecmd_event",
        summary: str = "Windows event",
        record_id: str | None = None,
        case_id: str | None = None,
        **overrides,
    ) -> NormalizedRecord:
        arguments = {
            "case_id": case_id or self.case.case_id,
            "source_type": source_type,
            "artifact_type": artifact_type,
            "timestamp": timestamp,
            "summary": summary,
            "hostname": "WIN-LAB01",
            "raw_reference": "analysis/tool_outputs/source.csv",
        }
        if record_id is not None:
            arguments["record_id"] = record_id
        arguments.update(overrides)
        return NormalizedRecord(**arguments)


class TimestampNormalizerTests(unittest.TestCase):
    def test_normalizes_iso_offset_and_naive_source_timezone(self) -> None:
        normalizer = TimestampNormalizer("UTC")

        offset = normalizer.normalize("2026-07-29T17:30:00+07:00")
        naive = normalizer.normalize(
            "2026-07-29T17:30:00",
            source_timezone="Asia/Bangkok",
        )

        self.assertEqual(
            offset,
            datetime(2026, 7, 29, 10, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(naive, offset)
        self.assertEqual(
            normalizer.to_text(offset),
            "2026-07-29T10:30:00.000Z",
        )

    def test_supports_unix_and_windows_filetime(self) -> None:
        normalizer = TimestampNormalizer()

        unix = normalizer.normalize("0", format_hint="unix")
        filetime = normalizer.normalize(
            "116444736000000000",
            format_hint="filetime",
        )

        self.assertEqual(unix, datetime(1970, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(filetime, unix)

    def test_rejects_invalid_timezone_hint_and_value(self) -> None:
        with self.assertRaisesRegex(ProcessingError, "Timezone"):
            TimestampNormalizer("Not/A-Timezone")

        normalizer = TimestampNormalizer()
        cases = (
            ({"value": "not-a-date"}, "Timestamp"),
            (
                {"value": "1", "format_hint": "unknown"},
                "format_hint",
            ),
            (
                {
                    "value": "2026-07-29T10:00:00",
                    "source_timezone": "Invalid/Zone",
                },
                "Timezone nguồn",
            ),
        )
        for kwargs, message in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ProcessingError, message):
                    normalizer.normalize(**kwargs)


class RecordNormalizerTests(ProcessingTestCase):
    def test_normalizes_aliases_numbers_and_preserves_unknown_values(self) -> None:
        source = {
            "CaseId": self.case.case_id,
            "Source": "hayabusa_event",
            "Artifact": "event_logs",
            "TimeCreated": "2026-07-29T17:00:00+07:00",
            "Title": "Đăng nhập đáng chú ý",
            "Computer Name": "WIN-LAB01",
            "EventID": "4624",
            "PID": "0x10",
            "RuleName": "Suspicious Logon",
        }

        record = RecordNormalizer().normalize(source)

        self.assertEqual(record.case_id, self.case.case_id)
        self.assertEqual(record.artifact_type, ArtifactType.EVENT_LOGS)
        self.assertEqual(record.event_id, 4624)
        self.assertEqual(record.process_id, 16)
        self.assertEqual(
            record.timestamp,
            datetime(2026, 7, 29, 10, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            record.attributes["RuleName"],
            "Suspicious Logon",
        )
        self.assertNotIn("EventID", record.attributes)

    def test_normalizing_model_returns_independent_record(self) -> None:
        original = self.record(
            attributes={"nested": {"value": 1}},
            record_id="REC-ORIGINAL",
        )

        normalized = RecordNormalizer().normalize(original)
        normalized.attributes["new"] = True

        self.assertEqual(normalized.to_dict()["record_id"], "REC-ORIGINAL")
        self.assertNotIn("new", original.attributes)

    def test_overrides_missing_context_and_raw_reference(self) -> None:
        record = RecordNormalizer().normalize(
            {
                "timestamp": "2026-07-29T10:00:00Z",
                "summary": "Generic row",
            },
            case_id=self.case.case_id,
            source_type="manual_import",
            artifact_type=ArtifactType.FILES,
            raw_reference="analysis/import.json",
        )

        self.assertEqual(record.case_id, self.case.case_id)
        self.assertEqual(record.source_type, "manual_import")
        self.assertEqual(record.artifact_type, ArtifactType.FILES)
        self.assertEqual(record.raw_reference, "analysis/import.json")

    def test_rejects_case_mismatch_missing_fields_and_bad_integer(self) -> None:
        valid = {
            "case_id": self.case.case_id,
            "source_type": "source",
            "artifact_type": "event_logs",
            "timestamp": "2026-07-29T10:00:00Z",
            "summary": "Summary",
        }
        cases = (
            (
                {**valid, "case_id": "CASE-20260729-999"},
                {"case_id": self.case.case_id},
                "khớp Case",
            ),
            (
                {key: value for key, value in valid.items() if key != "summary"},
                {},
                "summary",
            ),
            (
                {**valid, "event_id": "abc"},
                {},
                "số nguyên",
            ),
        )
        for data, kwargs, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ProcessingError, message):
                    RecordNormalizer().normalize(data, **kwargs)

    def test_normalize_many_reports_failing_record_number(self) -> None:
        values = (
            self.record(),
            {"timestamp": "bad"},
        )

        with self.assertRaisesRegex(ProcessingError, "Record 2"):
            RecordNormalizer().normalize_many(
                values,
                case_id=self.case.case_id,
            )


class LiveRecordLoaderTests(ProcessingTestCase):
    def test_loads_all_live_collectors_into_normalized_schema(self) -> None:
        samples = {
            "system.json": {
                "hostname": "WIN-LAB01",
                "os_name": "Windows 11",
                "current_user": "LAB\\alice",
            },
            "users.json": [
                {"name": "alice", "sid": "S-1-5-21-1000"}
            ],
            "processes.json": [
                {
                    "name": "powershell.exe",
                    "pid": 4242,
                    "parent_pid": 1000,
                    "executable_path": (
                        r"C:\Windows\System32\WindowsPowerShell"
                        r"\v1.0\powershell.exe"
                    ),
                    "command_line": "powershell.exe -EncodedCommand AAA",
                    "owner": "LAB\\alice",
                    "creation_date": "2026-07-01T00:00:00Z",
                }
            ],
            "network.json": [
                {
                    "protocol": "tcp",
                    "local_address": "10.0.0.5",
                    "local_port": 50123,
                    "remote_address": "8.8.8.8",
                    "remote_port": 443,
                    "state": "Established",
                    "pid": 4242,
                }
            ],
            "services.json": [
                {
                    "name": "DemoSvc",
                    "state": "Running",
                    "start_mode": "Auto",
                    "path_name": r"C:\Program Files\Demo\demo.exe",
                    "process_id": 5000,
                    "start_name": "LocalSystem",
                }
            ],
            "startup.json": [
                {
                    "name": "Updater",
                    "command": r"C:\Tools\updater.exe",
                    "location": "HKCU\\Run",
                    "user": "alice",
                }
            ],
        }
        for name, value in samples.items():
            write_json(self.paths.live / name, value)

        records = LiveRecordLoader(self.temp_path).load(self.case.case_id)

        self.assertEqual(len(records), 6)
        by_type = {record.artifact_type: record for record in records}
        process = by_type[ArtifactType.PROCESSES]
        self.assertEqual(process.source_type, "live_process")
        self.assertEqual(process.process_name, "powershell.exe")
        self.assertEqual(process.process_id, 4242)
        self.assertEqual(process.parent_process_id, 1000)
        self.assertIn("EncodedCommand", process.attributes["command_line"])
        self.assertEqual(
            process.raw_reference,
            "acquisition/live/processes.json",
        )
        network = by_type[ArtifactType.NETWORK]
        self.assertEqual(network.destination_ip, "8.8.8.8")
        self.assertEqual(network.process_id, 4242)
        service = by_type[ArtifactType.SERVICES]
        self.assertEqual(service.attributes["service_name"], "DemoSvc")
        self.assertTrue(
            all(record.hostname == "WIN-LAB01" for record in records)
        )
        self.assertTrue(
            all(record.record_id.startswith("REC-LIVE-") for record in records)
        )

    def test_rejects_invalid_live_json_shape(self) -> None:
        write_json(self.paths.live / "processes.json", {"pid": 1})

        with self.assertRaisesRegex(ProcessingError, "JSON array"):
            LiveRecordLoader(self.temp_path).load(self.case.case_id)


class RecordDeduplicatorTests(ProcessingTestCase):
    def test_removes_exact_duplicates_and_preserves_first_record(self) -> None:
        first = self.record(record_id="REC-FIRST")
        duplicate = self.record(record_id="REC-DUPLICATE")
        different = self.record(
            record_id="REC-DIFFERENT",
            summary="Another event",
        )

        result = RecordDeduplicator().deduplicate(
            (first, duplicate, different)
        )

        self.assertEqual(
            [record.record_id for record in result.records],
            ["REC-FIRST", "REC-DIFFERENT"],
        )
        self.assertEqual(
            result.duplicate_record_ids,
            ("REC-DUPLICATE",),
        )
        self.assertEqual(result.input_count, 3)

    def test_does_not_merge_records_with_different_source_reference(self) -> None:
        first = self.record(
            record_id="REC-1",
            raw_reference="analysis/source-a.csv",
        )
        second = self.record(
            record_id="REC-2",
            raw_reference="analysis/source-b.csv",
        )

        result = RecordDeduplicator().deduplicate((first, second))

        self.assertEqual(len(result.records), 2)
        self.assertEqual(result.duplicate_count, 0)

    def test_rejects_mixed_cases_and_non_record(self) -> None:
        with self.assertRaisesRegex(ProcessingError, "nhiều Case"):
            RecordDeduplicator().deduplicate(
                (
                    self.record(),
                    self.record(case_id="CASE-20260729-999"),
                )
            )
        with self.assertRaisesRegex(TypeError, "NormalizedRecord"):
            RecordDeduplicator().deduplicate((self.record(), {}))


class TimelineBuilderTests(ProcessingTestCase):
    def test_sorts_by_timestamp_then_artifact_priority(self) -> None:
        records = (
            self.record(
                record_id="REC-NETWORK",
                artifact_type=ArtifactType.NETWORK,
                source_type="live_network",
                summary="Network connection",
            ),
            self.record(
                record_id="REC-EVENT",
                artifact_type=ArtifactType.EVENT_LOGS,
                summary="Event log",
                event_id=4688,
            ),
            self.record(
                record_id="REC-EARLIER",
                timestamp="2026-07-29T09:59:00Z",
                artifact_type=ArtifactType.MFT,
                source_type="mftecmd_file",
                summary="Earlier file",
            ),
        )

        timeline = TimelineBuilder().build(records)

        self.assertEqual(
            [event.source_record_ids[0] for event in timeline],
            ["REC-EARLIER", "REC-EVENT", "REC-NETWORK"],
        )
        self.assertEqual(timeline[1].details["event_id"], 4688)
        self.assertEqual(timeline[1].event_type, "event_logs")

    def test_ids_are_deterministic_unique_and_link_source_records(self) -> None:
        record = self.record(record_id="REC-SAME")
        builder = TimelineBuilder()

        first = builder.build((record, record))
        second = builder.build((record, record))

        self.assertEqual(
            [event.timeline_event_id for event in first],
            [event.timeline_event_id for event in second],
        )
        self.assertNotEqual(
            first[0].timeline_event_id,
            first[1].timeline_event_id,
        )
        self.assertEqual(first[0].source_record_ids, ("REC-SAME",))

    def test_filters_inclusive_time_range(self) -> None:
        records = (
            self.record(
                record_id="REC-1",
                timestamp="2026-07-29T09:00:00Z",
            ),
            self.record(
                record_id="REC-2",
                timestamp="2026-07-29T10:00:00Z",
            ),
            self.record(
                record_id="REC-3",
                timestamp="2026-07-29T11:00:00Z",
            ),
        )

        timeline = TimelineBuilder().build(
            records,
            start="2026-07-29T10:00:00Z",
            end="2026-07-29T11:00:00Z",
        )

        self.assertEqual(
            [event.source_record_ids[0] for event in timeline],
            ["REC-2", "REC-3"],
        )

    def test_rejects_reverse_range_and_mixed_cases(self) -> None:
        with self.assertRaisesRegex(ProcessingError, "thời gian"):
            TimelineBuilder().build(
                (self.record(),),
                start="2026-07-29T11:00:00Z",
                end="2026-07-29T10:00:00Z",
            )
        with self.assertRaisesRegex(ProcessingError, "nhiều Case"):
            TimelineBuilder().build(
                (
                    self.record(),
                    self.record(case_id="CASE-20260729-999"),
                )
            )


class SchemaTests(ProcessingTestCase):
    def test_record_and_timeline_envelopes_round_trip(self) -> None:
        records = (self.record(record_id="REC-1"),)
        timeline = TimelineBuilder().build(records)

        loaded_records = parse_records_envelope(
            records_envelope(self.case.case_id, records),
            expected_case_id=self.case.case_id,
        )
        loaded_timeline = parse_timeline_envelope(
            timeline_envelope(self.case.case_id, timeline),
            expected_case_id=self.case.case_id,
        )

        self.assertEqual(loaded_records[0].to_dict(), records[0].to_dict())
        self.assertEqual(
            loaded_timeline[0].to_dict(),
            timeline[0].to_dict(),
        )

    def test_schema_rejects_version_count_and_case_mismatch(self) -> None:
        envelope = records_envelope(
            self.case.case_id,
            (self.record(),),
        )
        cases = (
            ({**envelope, "schema_version": 2}, "schema_version"),
            ({**envelope, "record_count": 99}, "record_count"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ProcessingError, message):
                    parse_records_envelope(data)
        with self.assertRaisesRegex(ProcessingError, "khớp Case"):
            parse_records_envelope(
                envelope,
                expected_case_id="CASE-20260729-999",
            )


class ProcessingPipelineTests(ProcessingTestCase):
    def test_pipeline_persists_records_timeline_summary_and_audit(self) -> None:
        duplicate = {
            "source": "hayabusa_event",
            "artifact": "event_logs",
            "timestamp": "2026-07-29T10:00:00Z",
            "title": "Suspicious logon",
            "event_id": 4624,
            "raw_reference": "analysis/hayabusa.csv",
        }
        network = {
            "source_type": "live_network",
            "artifact_type": "network",
            "timestamp": "2026-07-29T10:01:00Z",
            "summary": "Outbound connection",
            "destination_ip": "192.0.2.10",
        }
        pipeline = ProcessingPipeline(
            self.temp_path,
            actor="analyst",
        )

        result = pipeline.process(
            case_id=self.case.case_id,
            records=(duplicate, dict(duplicate), network),
        )

        self.assertEqual(result.input_count, 3)
        self.assertEqual(result.normalized_count, 2)
        self.assertEqual(result.duplicate_count, 1)
        self.assertEqual(result.timeline_count, 2)
        self.assertTrue(result.records_path.is_file())
        self.assertTrue(result.timeline_path.is_file())
        self.assertTrue(result.summary_path.is_file())
        self.assertEqual(
            pipeline.load_records(self.case.case_id)[0].summary,
            "Suspicious logon",
        )
        self.assertEqual(
            len(pipeline.load_timeline(self.case.case_id)),
            2,
        )
        self.assertEqual(
            read_json_object(result.records_path)["record_count"],
            2,
        )
        actions = [
            entry["action"]
            for entry in AuditLogger(
                self.case.case_id,
                self.temp_path,
            ).read_entries()
        ]
        self.assertEqual(actions[-1], "processing_completed")

    def test_pipeline_can_skip_deduplication_and_persistence(self) -> None:
        record = self.record(record_id="REC-SAME")
        pipeline = ProcessingPipeline(self.temp_path)

        result = pipeline.process(
            case_id=self.case.case_id,
            records=(record, record),
            persist=False,
            deduplicate=False,
        )

        self.assertEqual(result.input_count, 2)
        self.assertEqual(result.normalized_count, 2)
        self.assertEqual(result.duplicate_count, 0)
        self.assertEqual(
            len(
                {
                    event.timeline_event_id
                    for event in result.timeline
                }
            ),
            2,
        )
        self.assertIsNone(result.records_path)
        self.assertFalse(
            (self.paths.normalized / "records.json").exists()
        )

    def test_pipeline_rejects_closed_case_and_case_mismatch(self) -> None:
        pipeline = ProcessingPipeline(self.temp_path)
        with self.assertRaisesRegex(ProcessingError, "khớp Case"):
            pipeline.process(
                case_id=self.case.case_id,
                records=(
                    self.record(case_id="CASE-20260729-999"),
                ),
            )

        self.service.close_case(self.case.case_id)
        with self.assertRaises(CaseClosedError):
            pipeline.process(
                case_id=self.case.case_id,
                records=(self.record(),),
            )

    def test_pipeline_reports_invalid_processing_settings(self) -> None:
        settings_path = self.temp_path / "config" / "settings.json"
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        settings["processing"] = []
        settings_path.write_text(
            json.dumps(settings),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ProcessingError, "processing"):
            ProcessingPipeline(self.temp_path)


if __name__ == "__main__":
    unittest.main()
