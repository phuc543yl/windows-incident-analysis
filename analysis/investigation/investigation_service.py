"""Persist derived investigation views for a Case."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.json_utils import read_json_object, write_json
from models.alert import Alert
from models.finding import Finding
from models.incident import Incident
from models.normalized_record import NormalizedRecord
from models.timeline_event import TimelineEvent
from analysis.investigation.baseline import BaselineComparer
from analysis.investigation.entities import build_entity_index
from analysis.investigation.mitre_view import build_mitre_summary
from analysis.investigation.story import StoryBuilder


class InvestigationService:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.actor = actor.strip() or "analyst"

    def refresh_derived(
        self,
        case_id: str,
        *,
        records: tuple[NormalizedRecord, ...] = (),
        findings: tuple[Finding, ...] = (),
        alerts: tuple[Alert, ...] = (),
        incidents: tuple[Incident, ...] = (),
        timeline: tuple[TimelineEvent, ...] = (),
    ) -> dict[str, Any]:
        case = self.repository.load_case(case_id)
        paths = self.repository.paths(case.case_id)
        story = StoryBuilder().build(incidents, alerts, timeline)
        baseline = BaselineComparer(self.repository.project).compare(
            case.case_id,
            records,
        )
        mitre = build_mitre_summary(alerts, findings)
        entities = build_entity_index(records)
        write_json(
            paths.story_json,
            {
                "schema_version": 1,
                "case_id": case.case_id,
                "milestone_count": len(story),
                "milestones": [item.to_dict() for item in story],
            },
        )
        write_json(paths.baseline_diff_json, baseline.to_dict())
        write_json(paths.mitre_summary_json, {**mitre, "case_id": case.case_id})
        write_json(
            paths.entities_json,
            {
                "schema_version": 1,
                "case_id": case.case_id,
                **entities.to_dict(),
            },
        )
        return {
            "story": [item.to_dict() for item in story],
            "baseline": baseline.to_dict(),
            "mitre": mitre,
            "entities": entities.to_dict(),
        }

    def load_view(self, case_id: str) -> dict[str, Any]:
        case = self.repository.load_case(case_id)
        paths = self.repository.paths(case.case_id)
        return {
            "story": _optional(paths.story_json),
            "baseline": _optional(paths.baseline_diff_json),
            "mitre": _optional(paths.mitre_summary_json),
            "entities": _optional(paths.entities_json),
        }


def _optional(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return read_json_object(path)
