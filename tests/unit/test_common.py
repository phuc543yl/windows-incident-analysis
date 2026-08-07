from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common.constants import APP_NAME, APP_VERSION
from common.enums import CaseStatus, FindingSeverity, OperationMode
from common.exceptions import JsonFileError, UnsafePathError
from common.json_utils import (
    append_jsonl,
    read_json,
    read_json_object,
    write_json,
)
from common.logger import (
    configure_logging,
    get_logger,
    parse_log_level,
    shutdown_logging,
)
from common.paths import (
    cases_dir,
    ensure_base_directories,
    project_root,
    safe_join,
)
from common.time_utils import (
    ensure_utc,
    filename_timestamp,
    parse_timestamp,
    to_iso8601,
    validate_time_range,
    windows_filetime_to_datetime,
)


@dataclass(frozen=True)
class SampleRecord:
    name: str
    created_at: datetime
    path: Path
    status: CaseStatus


class CommonModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        self.addCleanup(shutdown_logging)

    def test_constants_are_available(self) -> None:
        self.assertTrue(APP_NAME)
        self.assertEqual(APP_VERSION, "0.1.0")

    def test_string_enums_are_json_friendly(self) -> None:
        cases = (
            (OperationMode.LOCAL, "local"),
            (CaseStatus.CLOSED, "closed"),
            (FindingSeverity.CRITICAL, "critical"),
        )
        for member, expected in cases:
            with self.subTest(member=member):
                self.assertEqual(str(member), expected)
                self.assertEqual(member, expected)

    def test_ensure_utc_treats_naive_datetime_as_utc(self) -> None:
        naive = datetime(2026, 7, 29, 9, 30, 0)
        expected = datetime(2026, 7, 29, 9, 30, tzinfo=timezone.utc)
        self.assertEqual(ensure_utc(naive), expected)

    def test_parse_timestamp_converts_offset_to_utc(self) -> None:
        value = parse_timestamp("2026-07-29T16:30:00+07:00")
        expected = datetime(2026, 7, 29, 9, 30, tzinfo=timezone.utc)
        self.assertEqual(value, expected)

    def test_parse_timestamp_supports_z_and_unix_seconds(self) -> None:
        from_text = parse_timestamp("1970-01-01T00:00:01Z")
        from_epoch = parse_timestamp(1)
        self.assertEqual(from_text, from_epoch)

    def test_parse_timestamp_rejects_invalid_text(self) -> None:
        for value in ("", "not-a-date"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_timestamp(value)

    def test_parse_timestamp_rejects_boolean(self) -> None:
        with self.assertRaises(TypeError):
            parse_timestamp(True)

    def test_to_iso8601_is_stable_utc_text(self) -> None:
        value = datetime(
            2026,
            7,
            29,
            16,
            30,
            tzinfo=timezone(timedelta(hours=7)),
        )
        self.assertEqual(to_iso8601(value), "2026-07-29T09:30:00.000Z")
        self.assertEqual(filename_timestamp(value), "20260729T093000Z")

    def test_validate_time_range_rejects_reverse_order(self) -> None:
        with self.assertRaises(ValueError):
            validate_time_range(
                "2026-07-29T10:00:00Z",
                "2026-07-29T09:00:00Z",
            )

    def test_windows_filetime_conversion(self) -> None:
        # 116444736000000000 is 1970-01-01T00:00:00Z.
        value = windows_filetime_to_datetime(116_444_736_000_000_000)
        self.assertEqual(value, datetime(1970, 1, 1, tzinfo=timezone.utc))

    def test_json_round_trip_supports_project_types(self) -> None:
        output = self.temp_path / "nested" / "record.json"
        record = SampleRecord(
            name="Máy thử nghiệm",
            created_at=datetime(2026, 7, 29, 9, 30, tzinfo=timezone.utc),
            path=Path("acquisition/live/system.json"),
            status=CaseStatus.OPEN,
        )

        self.assertEqual(write_json(output, record), output)
        loaded = read_json_object(output)

        self.assertEqual(loaded["name"], "Máy thử nghiệm")
        self.assertEqual(loaded["created_at"], "2026-07-29T09:30:00.000Z")
        self.assertEqual(loaded["path"], "acquisition/live/system.json")
        self.assertEqual(loaded["status"], "open")

    def test_read_json_returns_independent_default_copy(self) -> None:
        path = self.temp_path / "missing.json"
        default = {"items": []}
        first = read_json(path, default=default)
        first["items"].append("changed")
        second = read_json(path, default=default)
        self.assertEqual(second, {"items": []})

    def test_read_json_reports_invalid_content(self) -> None:
        invalid = self.temp_path / "invalid.json"
        invalid.write_text('{"broken": }', encoding="utf-8")
        with self.assertRaisesRegex(JsonFileError, "dòng"):
            read_json(invalid)

    def test_read_json_object_rejects_top_level_list(self) -> None:
        path = self.temp_path / "list.json"
        path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(JsonFileError, "object"):
            read_json_object(path)

    def test_append_jsonl_writes_one_record_per_line(self) -> None:
        output = self.temp_path / "audit.jsonl"
        append_jsonl(output, {"event": "case_created", "index": 1})
        append_jsonl(output, {"event": "collection_started", "index": 2})

        records = [
            json.loads(line)
            for line in output.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([record["index"] for record in records], [1, 2])

    def test_project_paths_can_be_scoped_to_temporary_root(self) -> None:
        self.assertEqual(project_root(self.temp_path), self.temp_path.resolve())
        expected = (self.temp_path / "runtime" / "cases").resolve()
        self.assertEqual(cases_dir(self.temp_path), expected)

    def test_ensure_base_directories_creates_expected_layout(self) -> None:
        directories = ensure_base_directories(self.temp_path)
        self.assertEqual(
            set(directories),
            {
                "config",
                "tools",
                "runtime",
                "cases",
                "agent_buffer",
                "logs",
            },
        )
        self.assertTrue(all(path.is_dir() for path in directories.values()))

    def test_safe_join_rejects_path_traversal(self) -> None:
        safe_path = safe_join(self.temp_path, "runtime", "cases")
        self.assertTrue(safe_path.is_relative_to(self.temp_path))
        with self.assertRaises(UnsafePathError):
            safe_join(self.temp_path, "..", "outside")

    def test_parse_log_level(self) -> None:
        self.assertEqual(parse_log_level("warning"), logging.WARNING)
        self.assertEqual(parse_log_level(logging.DEBUG), logging.DEBUG)
        with self.assertRaises(ValueError):
            parse_log_level("not-a-level")

    def test_logging_writes_once_and_redacts_secrets(self) -> None:
        stream = io.StringIO()
        log_file = self.temp_path / "logs" / "application.log"

        configure_logging(
            level="INFO",
            log_file=log_file,
            console=True,
            stream=stream,
        )
        # Reconfiguration must replace handlers rather than duplicate them.
        logger = configure_logging(
            level="INFO",
            log_file=log_file,
            console=True,
            stream=stream,
        )
        get_logger("test").info(
            "token=secret-value Authorization: Bearer abc123"
        )

        for handler in logger.handlers:
            handler.flush()

        console_text = stream.getvalue()
        file_text = log_file.read_text(encoding="utf-8")
        self.assertEqual(console_text.count("windows_forensic.test"), 1)
        self.assertNotIn("secret-value", console_text)
        self.assertNotIn("abc123", console_text)
        self.assertIn("token=***", console_text)
        self.assertIn("Bearer ***", console_text)
        self.assertNotIn("secret-value", file_text)
        self.assertNotIn("abc123", file_text)


if __name__ == "__main__":
    unittest.main()
