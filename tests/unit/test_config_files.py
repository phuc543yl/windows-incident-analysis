from __future__ import annotations

import re
import unittest
from pathlib import Path, PurePosixPath
from typing import Any

from common.json_utils import read_json_object

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = PROJECT_ROOT / "config"
PROFILE_ROOT = CONFIG_ROOT / "investigation_profiles"

EXPECTED_CONFIG_FILES = {
    "settings.json",
    "agent.json",
    "tool_integrations.json",
    "detection_rules.json",
    "mitre_mapping.json",
}

EXPECTED_PROFILES = {
    "account_compromise",
    "endpoint_compromise",
    "general_investigation",
    "log_tampering",
    "service_disruption",
}

LIVE_COLLECTORS = {
    "system",
    "users",
    "processes",
    "network",
    "services",
    "startup",
}

ARTIFACT_COLLECTORS = {
    "event_logs",
    "prefetch",
    "amcache",
    "registry",
    "mft",
    "scheduled_tasks",
    "firewall_logs",
    "files",
    "memory",
}

SEVERITIES = {"info", "low", "medium", "high", "critical"}
MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def load_config(name: str) -> dict[str, Any]:
    return read_json_object(CONFIG_ROOT / name)


def load_profiles() -> dict[str, dict[str, Any]]:
    return {
        path.stem: read_json_object(path)
        for path in sorted(PROFILE_ROOT.glob("*.json"))
    }


def iter_keys(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from iter_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_keys(nested)


class ConfigFileTests(unittest.TestCase):
    def test_required_config_files_exist_and_are_objects(self) -> None:
        existing = {path.name for path in CONFIG_ROOT.glob("*.json")}
        self.assertTrue(EXPECTED_CONFIG_FILES.issubset(existing))
        for name in EXPECTED_CONFIG_FILES:
            with self.subTest(name=name):
                data = load_config(name)
                self.assertEqual(data["schema_version"], 1)

    def test_settings_use_safe_relative_paths(self) -> None:
        settings = load_config("settings.json")
        paths = settings["paths"]
        for name, configured_path in paths.items():
            with self.subTest(name=name):
                portable_path = PurePosixPath(configured_path)
                self.assertFalse(portable_path.is_absolute())
                self.assertNotIn("..", portable_path.parts)
                self.assertNotIn("\\", configured_path)

        self.assertEqual(settings["case"]["hash_algorithm"], "sha256")
        self.assertEqual(settings["collection"]["default_mode"], "local")
        self.assertGreater(settings["collection"]["timeout_seconds"], 0)

    def test_agent_does_not_contain_a_hardcoded_token(self) -> None:
        agent = load_config("agent.json")
        self.assertNotIn("token", set(iter_keys(agent)))
        authentication = agent["authentication"]
        self.assertTrue(authentication["enabled"])
        self.assertEqual(
            authentication["token_env"],
            "WINDOWS_FORENSIC_AGENT_TOKEN",
        )
        self.assertFalse(authentication["allow_token_in_config"])
        self.assertEqual(agent["agent"]["host"], "127.0.0.1")

    def test_tool_integrations_are_unique_and_portable(self) -> None:
        tools = load_config("tool_integrations.json")["tools"]
        tool_ids = [tool["id"] for tool in tools]
        self.assertEqual(len(tool_ids), len(set(tool_ids)))
        self.assertIn("hayabusa", tool_ids)
        self.assertIn("evtxecmd", tool_ids)

        for tool in tools:
            with self.subTest(tool=tool["id"]):
                executable = tool["executable"]
                portable_path = PurePosixPath(executable)
                self.assertFalse(portable_path.is_absolute())
                self.assertNotIn("..", portable_path.parts)
                self.assertNotIn("\\", executable)
                self.assertGreater(tool["timeout_seconds"], 0)
                self.assertTrue(tool["supported_artifacts"])

    def test_detection_rules_have_valid_fields(self) -> None:
        rules = load_config("detection_rules.json")["rules"]
        rule_ids = [rule["id"] for rule in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))

        for rule in rules:
            with self.subTest(rule=rule["id"]):
                self.assertIn(rule["severity"], SEVERITIES)
                self.assertGreaterEqual(rule["risk_score"], 0)
                self.assertLessEqual(rule["risk_score"], 100)
                self.assertTrue(rule["source_types"])
                self.assertTrue(rule["parameters"])
                for technique_id in rule["mitre_techniques"]:
                    self.assertRegex(technique_id, MITRE_ID_PATTERN)

    def test_every_rule_has_consistent_mitre_mapping(self) -> None:
        rules = load_config("detection_rules.json")["rules"]
        mappings = load_config("mitre_mapping.json")["mappings"]
        self.assertEqual({rule["id"] for rule in rules}, set(mappings))

        for rule in rules:
            mapped_ids = {
                item["technique_id"]
                for item in mappings[rule["id"]]
            }
            with self.subTest(rule=rule["id"]):
                self.assertEqual(
                    set(rule["mitre_techniques"]),
                    mapped_ids,
                )

    def test_profiles_exist_and_reference_known_components(self) -> None:
        profiles = load_profiles()
        self.assertEqual(set(profiles), EXPECTED_PROFILES)

        tool_ids = {
            tool["id"]
            for tool in load_config("tool_integrations.json")["tools"]
        }
        rule_ids = {
            rule["id"]
            for rule in load_config("detection_rules.json")["rules"]
        }

        for file_stem, profile in profiles.items():
            with self.subTest(profile=file_stem):
                self.assertEqual(profile["profile_id"], file_stem)
                self.assertEqual(profile["schema_version"], 1)
                self.assertGreater(profile["default_time_window_hours"], 0)
                self.assertTrue(
                    set(profile["live_collectors"]).issubset(LIVE_COLLECTORS)
                )
                self.assertTrue(
                    set(profile["artifact_collectors"]).issubset(
                        ARTIFACT_COLLECTORS
                    )
                )
                self.assertTrue(set(profile["tools"]).issubset(tool_ids))
                self.assertTrue(
                    set(profile["detection_rules"]).issubset(rule_ids)
                )
                self.assertFalse(
                    set(profile["required_artifacts"])
                    & set(profile["optional_artifacts"])
                )
                self.assertTrue(
                    set(profile["required_artifacts"]).issubset(
                        profile["artifact_collectors"]
                    )
                )
                self.assertTrue(
                    set(profile["optional_artifacts"]).issubset(
                        profile["artifact_collectors"]
                    )
                )

    def test_general_profile_matches_settings_default(self) -> None:
        settings = load_config("settings.json")
        profiles = load_profiles()
        default_profile = settings["collection"]["default_profile"]
        self.assertIn(default_profile, profiles)
        self.assertEqual(default_profile, "general_investigation")


if __name__ == "__main__":
    unittest.main()
