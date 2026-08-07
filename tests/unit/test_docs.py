from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCS = PROJECT_ROOT / "docs"
REQUIRED_DOCUMENTS = {
    "architecture.md",
    "evidence_schema.md",
    "agent_protocol.md",
    "tool_integrations.md",
    "demo_scenarios.md",
}
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
JSON_FENCE_PATTERN = re.compile(
    r"```json\s*\n(.*?)\n```",
    flags=re.DOTALL | re.IGNORECASE,
)


def read_document(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


class DocumentationTests(unittest.TestCase):
    def test_required_documents_exist_and_are_substantial(self) -> None:
        actual = {path.name for path in DOCS.glob("*.md")}

        self.assertTrue(REQUIRED_DOCUMENTS.issubset(actual))
        for name in REQUIRED_DOCUMENTS:
            with self.subTest(document=name):
                content = read_document(name)
                self.assertTrue(content.startswith("# "))
                self.assertGreater(len(content), 1500)
                self.assertIn("\n## ", content)

    def test_local_markdown_links_resolve(self) -> None:
        for name in REQUIRED_DOCUMENTS:
            document = DOCS / name
            content = document.read_text(encoding="utf-8")
            for target in MARKDOWN_LINK_PATTERN.findall(content):
                with self.subTest(document=name, target=target):
                    normalized = target.split("#", maxsplit=1)[0].strip()
                    if (
                        not normalized
                        or "://" in normalized
                        or normalized.startswith("mailto:")
                    ):
                        continue
                    self.assertTrue(
                        (document.parent / normalized).resolve().exists(),
                        f"Liên kết không tồn tại: {name} -> {target}",
                    )

    def test_all_json_examples_are_valid_objects(self) -> None:
        example_count = 0
        for name in REQUIRED_DOCUMENTS:
            for raw_json in JSON_FENCE_PATTERN.findall(read_document(name)):
                with self.subTest(document=name, sample=example_count):
                    value = json.loads(raw_json)
                    self.assertIsInstance(value, dict)
                example_count += 1

        self.assertGreaterEqual(example_count, 7)

    def test_architecture_documents_current_layers_and_modes(self) -> None:
        content = read_document("architecture.md")

        for directory in (
            "case_management/",
            "collection/",
            "evidence/",
            "integrations/",
            "processing/",
            "analysis/",
            "reporting/",
            "ui/",
        ):
            with self.subTest(directory=directory):
                self.assertIn(f"`{directory}`", content)
        self.assertIn("Local Mode", content)
        self.assertIn("Agent Mode", content)
        self.assertIn("suspected", content)
        self.assertIn("SHA-256", content)

    def test_evidence_schema_covers_model_and_integrity_fields(self) -> None:
        content = read_document("evidence_schema.md")

        for field in (
            "evidence_id",
            "artifact_type",
            "source_path",
            "stored_path",
            "collector_id",
            "hostname",
            "sha256",
            "size_bytes",
            "collected_at",
            "raw_reference",
        ):
            with self.subTest(field=field):
                self.assertIn(f"`{field}`", content)
        self.assertIn("chain_of_custody.json", content)
        self.assertIn("BundleReader", content)

    def test_agent_protocol_matches_route_contract(self) -> None:
        content = read_document("agent_protocol.md")

        endpoints = (
            "/api/v1/health",
            "/api/v1/tasks",
            "/api/v1/tasks/{task_id}",
            "/api/v1/tasks/{task_id}/bundle",
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                self.assertIn(endpoint, content)
        self.assertIn("X-Agent-Token", content)
        self.assertIn("X-Content-SHA256", content)
        self.assertIn("X-Agent-Task-ID", content)
        self.assertIn("application/zip", content)
        self.assertIn("đóng response", content)

    def test_tool_document_tracks_every_configured_tool(self) -> None:
        config = json.loads(
            (
                PROJECT_ROOT / "config" / "tool_integrations.json"
            ).read_text(encoding="utf-8")
        )
        content = read_document("tool_integrations.md")

        for tool in config["tools"]:
            with self.subTest(tool=tool["id"]):
                self.assertIn(f"`{tool['id']}`", content)
                self.assertIn(f"`{tool['executable']}`", content)
                for artifact in tool["supported_artifacts"]:
                    self.assertIn(f"`{artifact}`", content)

    def test_demo_document_tracks_scenario_fixtures(self) -> None:
        content = read_document("demo_scenarios.md")
        scenario_directory = PROJECT_ROOT / "tests" / "fixtures" / "scenarios"

        for path in sorted(scenario_directory.glob("*.json")):
            scenario = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(scenario=scenario["scenario_id"]):
                self.assertIn(f"`{scenario['scenario_id']}`", content)
                self.assertIn(f"`{scenario['profile_id']}`", content)
                self.assertIn(
                    f"`{scenario['expected_incident_type']}`",
                    content,
                )
                for rule_id in scenario["expected_rule_ids"]:
                    self.assertIn(f"`{rule_id}`", content)
                for impact in scenario["confirmation_cia_impacts"]:
                    self.assertIn(f"`{impact}`", content)

    def test_docs_do_not_claim_automatic_incident_confirmation(self) -> None:
        architecture = read_document("architecture.md")
        scenarios = read_document("demo_scenarios.md")

        self.assertIn("Chuyên viên phải", architecture)
        self.assertIn("incident tự động vẫn là `suspected`", scenarios)
        self.assertIn("CIA rỗng", scenarios)


if __name__ == "__main__":
    unittest.main()
