"""Version previous analysis results before a Case is analyzed again."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.json_utils import write_json
from common.time_utils import utc_now_iso
from models import new_id


@dataclass(frozen=True, slots=True)
class AnalysisVersion:
    """One immutable snapshot of superseded analysis outputs."""

    version_id: str
    case_id: str
    path: Path
    archived_at: str
    files: tuple[str, ...]


class AnalysisHistoryService:
    """Archive the current result files without deleting evidence or outputs."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.actor = actor.strip() or "analyst"

    def archive_current(self, case_id: str) -> AnalysisVersion | None:
        case = self.repository.load_case(case_id)
        paths = self.repository.paths(case.case_id)
        sources = tuple(
            path
            for path in (
                paths.findings_json,
                paths.alerts_json,
                paths.incidents_json,
            )
            if path.is_file()
        )
        if not sources:
            return None

        version_id = new_id("ANVER")
        archived_at = utc_now_iso()
        destination = paths.analysis_history / version_id
        destination.mkdir(parents=True, exist_ok=False)
        try:
            for source in sources:
                shutil.copy2(source, destination / source.name)
            write_json(
                destination / "version.json",
                {
                    "schema_version": 1,
                    "version_id": version_id,
                    "case_id": case.case_id,
                    "archived_at": archived_at,
                    "archived_by": self.actor,
                    "files": [source.name for source in sources],
                },
            )
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise

        version = AnalysisVersion(
            version_id=version_id,
            case_id=case.case_id,
            path=destination,
            archived_at=archived_at,
            files=tuple(source.name for source in sources),
        )
        AuditLogger(case.case_id, self.repository.project).log(
            "analysis_results_archived",
            actor=self.actor,
            details={
                "version_id": version.version_id,
                "history_path": destination.relative_to(
                    paths.root
                ).as_posix(),
                "files": list(version.files),
            },
        )
        return version

    def list_versions(self, case_id: str) -> tuple[Path, ...]:
        case = self.repository.load_case(case_id)
        history = self.repository.paths(case.case_id).analysis_history
        if not history.is_dir():
            return ()
        return tuple(
            sorted(
                (
                    path
                    for path in history.iterdir()
                    if path.is_dir() and (path / "version.json").is_file()
                ),
                key=lambda path: path.name,
            )
        )
