"""Deterministic filesystem layout for one investigation Case."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.paths import cases_dir, project_root, safe_join
from models.case import Case

RAW_ARTIFACT_DIRECTORIES = {
    "event_logs": "EventLogs",
    "prefetch": "Prefetch",
    "amcache": "Amcache",
    "registry": "Registry",
    "mft": "NTFS",
    "scheduled_tasks": "ScheduledTasks",
    "firewall_logs": "FirewallLogs",
    "files": "Files",
    "memory": "Memory",
}


@dataclass(frozen=True, slots=True)
class CasePaths:
    """All paths owned by a single Case."""

    case_id: str
    project: Path

    def __post_init__(self) -> None:
        normalized_id = self.case_id.strip().upper()
        if not Case.CASE_ID_PATTERN.fullmatch(normalized_id):
            raise ValueError(
                "case_id phải có dạng CASE-YYYYMMDD-NNN, "
                "ví dụ CASE-20260729-001."
            )
        object.__setattr__(self, "case_id", normalized_id)
        object.__setattr__(self, "project", project_root(self.project))

    @property
    def root(self) -> Path:
        return safe_join(cases_dir(self.project), self.case_id)

    @property
    def case_json(self) -> Path:
        return safe_join(self.root, "case.json")

    @property
    def target_json(self) -> Path:
        return safe_join(self.root, "target.json")

    @property
    def collection_plan_json(self) -> Path:
        return safe_join(self.root, "collection_plan.json")

    @property
    def acquisition(self) -> Path:
        return safe_join(self.root, "acquisition")

    @property
    def live(self) -> Path:
        return safe_join(self.acquisition, "live")

    @property
    def raw(self) -> Path:
        return safe_join(self.acquisition, "raw")

    @property
    def manifest_json(self) -> Path:
        return safe_join(self.acquisition, "manifest.json")

    @property
    def hashes_sha256(self) -> Path:
        return safe_join(self.acquisition, "hashes.sha256")

    @property
    def chain_of_custody_json(self) -> Path:
        return safe_join(self.acquisition, "chain_of_custody.json")

    @property
    def bundles(self) -> Path:
        return safe_join(self.root, "bundles")

    @property
    def analysis(self) -> Path:
        return safe_join(self.root, "analysis")

    @property
    def tool_outputs(self) -> Path:
        return safe_join(self.analysis, "tool_outputs")

    @property
    def normalized(self) -> Path:
        return safe_join(self.analysis, "normalized")

    @property
    def analysis_history(self) -> Path:
        return safe_join(self.analysis, "history")

    @property
    def findings_json(self) -> Path:
        return safe_join(self.analysis, "findings.json")

    @property
    def alerts_json(self) -> Path:
        return safe_join(self.analysis, "alerts.json")

    @property
    def incidents_json(self) -> Path:
        return safe_join(self.analysis, "incidents.json")

    @property
    def timeline_json(self) -> Path:
        return safe_join(self.analysis, "timeline.json")

    @property
    def story_json(self) -> Path:
        return safe_join(self.analysis, "story.json")

    @property
    def baseline_diff_json(self) -> Path:
        return safe_join(self.analysis, "baseline_diff.json")

    @property
    def mitre_summary_json(self) -> Path:
        return safe_join(self.analysis, "mitre_summary.json")

    @property
    def entities_json(self) -> Path:
        return safe_join(self.analysis, "entities.json")

    @property
    def checklist_json(self) -> Path:
        return safe_join(self.analyst, "checklist.json")

    @property
    def analyst(self) -> Path:
        return safe_join(self.root, "analyst")

    @property
    def notes_json(self) -> Path:
        return safe_join(self.analyst, "notes.json")

    @property
    def conclusion_json(self) -> Path:
        return safe_join(self.analyst, "conclusion.json")

    @property
    def recommendations_json(self) -> Path:
        return safe_join(self.analyst, "recommendations.json")

    @property
    def reports(self) -> Path:
        return safe_join(self.root, "reports")

    @property
    def logs(self) -> Path:
        return safe_join(self.root, "logs")

    @property
    def audit_log(self) -> Path:
        return safe_join(self.logs, "audit.log")

    @property
    def collection_log(self) -> Path:
        return safe_join(self.logs, "collection.log")

    @property
    def tool_runs_log(self) -> Path:
        return safe_join(self.logs, "tool_runs.log")

    @property
    def errors_log(self) -> Path:
        return safe_join(self.logs, "errors.log")

    def raw_artifact_dir(self, artifact_id: str) -> Path:
        try:
            directory_name = RAW_ARTIFACT_DIRECTORIES[artifact_id]
        except KeyError as exc:
            raise ValueError(f"Artifact directory không hợp lệ: {artifact_id}") from exc
        return safe_join(self.raw, directory_name)

    def directories(self) -> tuple[Path, ...]:
        raw_directories = tuple(
            self.raw_artifact_dir(artifact_id)
            for artifact_id in RAW_ARTIFACT_DIRECTORIES
        )
        return (
            self.root,
            self.acquisition,
            self.live,
            self.raw,
            *raw_directories,
            self.bundles,
            self.analysis,
            self.tool_outputs,
            self.normalized,
            self.analysis_history,
            self.analyst,
            self.reports,
            self.logs,
        )

    def create_layout(self) -> None:
        if self.root.exists():
            raise FileExistsError(f"Case đã tồn tại: {self.case_id}")
        self.root.mkdir(parents=True, exist_ok=False)
        for directory in self.directories()[1:]:
            directory.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "root": self.root.as_posix(),
            "case_json": self.case_json.as_posix(),
            "target_json": self.target_json.as_posix(),
            "collection_plan_json": self.collection_plan_json.as_posix(),
            "acquisition": self.acquisition.as_posix(),
            "analysis": self.analysis.as_posix(),
            "analyst": self.analyst.as_posix(),
            "reports": self.reports.as_posix(),
            "logs": self.logs.as_posix(),
        }


def get_case_paths(
    case_id: str,
    root: str | Path | None = None,
) -> CasePaths:
    return CasePaths(case_id=case_id, project=project_root(root))
