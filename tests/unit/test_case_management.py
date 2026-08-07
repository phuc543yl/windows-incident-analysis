from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_paths import RAW_ARTIFACT_DIRECTORIES, get_case_paths
from case_management.case_service import CaseService
from case_management.profile_service import ProfileService
from common.enums import CaseStatus, OperationMode
from common.exceptions import (
    CaseClosedError,
    CaseNotFoundError,
    ConfigurationError,
    JsonFileError,
)
from common.json_utils import read_json_object

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASE_ID_PATTERN = re.compile(r"^CASE-\d{8}-\d{3,6}$")


class CaseManagementTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.temp_path = Path(temporary_directory.name)
        self.addCleanup(temporary_directory.cleanup)
        shutil.copytree(
            PROJECT_ROOT / "config",
            self.temp_path / "config",
        )
        self.service = CaseService(self.temp_path, actor="analyst")

    def create_case(self, **overrides):
        arguments = {
            "title": "Điều tra máy Windows",
            "target_hostname": "WIN-LAB01",
            "profile_id": "general_investigation",
        }
        arguments.update(overrides)
        return self.service.create_case(**arguments)

    def test_create_case_writes_metadata_and_expected_layout(self) -> None:
        case = self.create_case(
            description="Kiểm tra dấu hiệu xâm nhập.",
            target_ip_addresses=("192.0.2.10",),
            tags=("windows", "triage"),
        )
        paths = self.service.repository.paths(case.case_id)

        self.assertRegex(case.case_id, CASE_ID_PATTERN)
        self.assertEqual(case.status, CaseStatus.OPEN)
        self.assertTrue(all(path.is_dir() for path in paths.directories()))
        self.assertTrue(paths.case_json.is_file())
        self.assertTrue(paths.target_json.is_file())
        self.assertTrue(paths.collection_plan_json.is_file())
        self.assertTrue(paths.audit_log.is_file())

        for artifact_id in RAW_ARTIFACT_DIRECTORIES:
            with self.subTest(artifact_id=artifact_id):
                self.assertTrue(paths.raw_artifact_dir(artifact_id).is_dir())

    def test_open_case_and_context_restore_all_models(self) -> None:
        created = self.create_case(target_ip_addresses=("192.0.2.20",))

        opened = self.service.open_case(created.case_id)
        context = self.service.get_case_context(created.case_id)

        self.assertEqual(opened.to_dict(), created.to_dict())
        self.assertEqual(context["case"]["case_id"], created.case_id)
        self.assertEqual(context["target"]["hostname"], "WIN-LAB01")
        self.assertEqual(
            context["target"]["ip_addresses"],
            ["192.0.2.20"],
        )
        self.assertEqual(
            context["collection_plan"]["profile_id"],
            "general_investigation",
        )

    def test_create_case_uses_profile_hypothesis_and_collectors(self) -> None:
        case = self.create_case(profile_id="endpoint_compromise")
        profile = ProfileService(self.temp_path).get_profile(
            "endpoint_compromise"
        )
        plan = self.service.repository.load_collection_plan(case.case_id)

        self.assertEqual(case.hypothesis, profile["hypothesis"])
        self.assertEqual(
            plan.live_collectors,
            tuple(profile["live_collectors"]),
        )
        self.assertEqual(
            plan.artifact_collectors,
            tuple(profile["artifact_collectors"]),
        )
        self.assertEqual(
            plan.options["detection_rules"],
            profile["detection_rules"],
        )

    def test_agent_mode_requires_and_saves_agent_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "target_agent_id"):
            self.create_case(mode=OperationMode.AGENT)

        case = self.create_case(
            title="Điều tra từ xa",
            target_hostname="WIN-AGENT01",
            mode="agent",
            target_agent_id="AGENT-001",
        )
        target = self.service.repository.load_target(case.case_id)
        plan = self.service.repository.load_collection_plan(case.case_id)

        self.assertEqual(case.mode, OperationMode.AGENT)
        self.assertEqual(target.agent_id, "AGENT-001")
        self.assertEqual(plan.target_agent_id, "AGENT-001")

    def test_case_ids_increase_and_skip_existing_directory(self) -> None:
        first = self.create_case()
        date_component = first.case_id.split("-")[1]
        reserved = (
            self.temp_path
            / "runtime"
            / "cases"
            / f"CASE-{date_component}-007"
        )
        reserved.mkdir()

        second = self.create_case(target_hostname="WIN-LAB02")

        self.assertEqual(second.case_id, f"CASE-{date_component}-008")

    def test_update_case_and_target_are_persisted_and_audited(self) -> None:
        case = self.create_case()

        updated_case = self.service.update_case(
            case.case_id,
            title="Điều tra PowerShell",
            description="Phạm vi đã cập nhật.",
            tags=("powershell", "high-priority"),
            metadata={"ticket": "IR-001"},
        )
        updated_target = self.service.update_target(
            case.case_id,
            os_name="Windows 11",
            os_version="24H2",
            architecture="x64",
            domain="LAB",
            current_user="LAB\\analyst",
            ip_addresses=("192.0.2.30", "2001:db8::30"),
        )

        self.assertEqual(updated_case.title, "Điều tra PowerShell")
        self.assertEqual(updated_case.metadata["ticket"], "IR-001")
        self.assertEqual(updated_target.os_name, "Windows 11")
        self.assertEqual(
            self.service.repository.load_target(case.case_id).ip_addresses,
            ("192.0.2.30", "2001:db8::30"),
        )
        actions = [
            entry["action"]
            for entry in AuditLogger(
                case.case_id,
                self.temp_path,
            ).read_entries()
        ]
        self.assertEqual(
            actions,
            ["case_created", "case_updated", "target_updated"],
        )

    def test_update_target_rejects_invalid_ip_without_saving_it(self) -> None:
        case = self.create_case(target_ip_addresses=("192.0.2.40",))

        with self.assertRaisesRegex(ValueError, "IP không hợp lệ"):
            self.service.update_target(
                case.case_id,
                ip_addresses=("not-an-ip",),
            )

        target = self.service.repository.load_target(case.case_id)
        self.assertEqual(target.ip_addresses, ("192.0.2.40",))

    def test_close_case_writes_conclusion_and_blocks_changes(self) -> None:
        case = self.create_case()

        closed = self.service.close_case(
            case.case_id,
            conclusion="Không còn hoạt động độc hại.",
        )
        paths = self.service.repository.paths(case.case_id)
        conclusion = read_json_object(paths.conclusion_json)

        self.assertEqual(closed.status, CaseStatus.CLOSED)
        self.assertIsNotNone(closed.closed_at)
        self.assertEqual(conclusion["case_id"], case.case_id)
        self.assertEqual(
            conclusion["conclusion"],
            "Không còn hoạt động độc hại.",
        )
        self.assertEqual(conclusion["closed_by"], "analyst")
        with self.assertRaises(CaseClosedError):
            self.service.update_case(case.case_id, description="Không hợp lệ")
        with self.assertRaises(CaseClosedError):
            self.service.close_case(case.case_id)

    def test_list_cases_filters_by_status(self) -> None:
        open_case = self.create_case(target_hostname="WIN-OPEN")
        closed_case = self.create_case(target_hostname="WIN-CLOSED")
        self.service.close_case(closed_case.case_id)

        self.assertEqual(
            [item.case_id for item in self.service.list_cases("open")],
            [open_case.case_id],
        )
        self.assertEqual(
            [item.case_id for item in self.service.list_cases("closed")],
            [closed_case.case_id],
        )
        with self.assertRaisesRegex(ValueError, "status không hợp lệ"):
            self.service.list_cases("deleted")

    def test_missing_case_raises_domain_error(self) -> None:
        with self.assertRaises(CaseNotFoundError):
            self.service.open_case("CASE-20260729-999")

    def test_invalid_case_id_and_artifact_id_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "CASE-YYYYMMDD-NNN"):
            get_case_paths("../outside", self.temp_path)

        paths = get_case_paths("CASE-20260729-001", self.temp_path)
        with self.assertRaisesRegex(ValueError, "Artifact directory"):
            paths.raw_artifact_dir("unknown")

    def test_profile_service_lists_profiles_and_returns_a_copy(self) -> None:
        profiles = ProfileService(self.temp_path)
        listed_ids = {
            profile["profile_id"]
            for profile in profiles.list_profiles()
        }
        first = profiles.get_profile("general_investigation")
        first["live_collectors"].append("changed")
        second = profiles.get_profile("general_investigation")

        self.assertIn("general_investigation", listed_ids)
        self.assertNotIn("changed", second["live_collectors"])
        self.assertTrue(profiles.profile_exists("endpoint_compromise"))
        self.assertFalse(profiles.profile_exists("../invalid"))
        with self.assertRaises(ConfigurationError):
            profiles.get_profile("missing_profile")

    def test_audit_logger_redacts_nested_sensitive_values(self) -> None:
        case = self.create_case()
        logger = AuditLogger(case.case_id, self.temp_path)

        entry = logger.log(
            "authentication_test",
            actor="tester",
            details={
                "token": "secret-token",
                "nested": {
                    "api_key": "secret-key",
                    "safe": "visible",
                },
            },
        )

        self.assertEqual(entry["details"]["token"], "***")
        self.assertEqual(entry["details"]["nested"]["api_key"], "***")
        self.assertEqual(entry["details"]["nested"]["safe"], "visible")
        self.assertNotIn(
            "secret-token",
            logger.paths.audit_log.read_text(encoding="utf-8"),
        )

    def test_audit_logger_reports_invalid_json_line(self) -> None:
        case = self.create_case()
        logger = AuditLogger(case.case_id, self.temp_path)
        logger.paths.audit_log.write_text("not-json\n", encoding="utf-8")

        with self.assertRaisesRegex(JsonFileError, "dòng 1"):
            logger.read_entries()

    def test_repository_reports_malformed_case_json(self) -> None:
        case = self.create_case()
        paths = self.service.repository.paths(case.case_id)
        paths.case_json.write_text(
            json.dumps({"case_id": case.case_id}),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(JsonFileError, "case.json"):
            self.service.open_case(case.case_id)


if __name__ == "__main__":
    unittest.main()
