"""Controller for analysis results, timeline, and analyst decisions."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from analysis.analysis_service import AnalysisService
from common.exceptions import ProcessingError
from models.normalized_record import NormalizedRecord
from models.timeline_event import TimelineEvent
from processing.processing_pipeline import ProcessingPipeline
from ui.controllers.case_controller import CaseController


class AnalysisController:
    def __init__(
        self,
        case_controller: CaseController,
        root: str | Path | None = None,
        *,
        service: AnalysisService | None = None,
        pipeline: ProcessingPipeline | None = None,
    ) -> None:
        self.case_controller = case_controller
        self.service = service or AnalysisService(root)
        self.pipeline = pipeline or ProcessingPipeline(root)

    def analyze(
        self,
        *,
        records: Iterable[NormalizedRecord] | None = None,
        timeline: Iterable[TimelineEvent] | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        result = self.service.analyze(
            case_id=case_id,
            records=records,
            timeline=timeline,
            **({"on_progress": on_progress} if on_progress is not None else {}),
        )
        return {
            "case_id": result.case_id,
            "record_count": result.record_count,
            "finding_count": result.finding_count,
            "alert_count": result.alert_count,
            "incident_count": result.incident_count,
            "findings": [item.to_dict() for item in result.findings],
            "alerts": [item.to_dict() for item in result.alerts],
            "incidents": [item.to_dict() for item in result.incidents],
        }

    def refresh(self) -> dict[str, list[dict[str, Any]]]:
        case_id = self.case_controller.require_case_id()
        try:
            timeline = self.pipeline.load_timeline(case_id)
        except ProcessingError:
            timeline = ()
        return {
            "findings": [
                item.to_dict() for item in self.service.load_findings(case_id)
            ],
            "alerts": [item.to_dict() for item in self.service.load_alerts(case_id)],
            "incidents": [
                item.to_dict() for item in self.service.load_incidents(case_id)
            ],
            "timeline": [item.to_dict() for item in timeline],
        }

    def set_incident_status(
        self,
        incident_id: str,
        status: str,
        *,
        conclusion: str,
        cia_impacts: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        case_id = self.case_controller.require_case_id()
        incident = self.service.set_incident_status(
            case_id,
            incident_id,
            status,
            conclusion=conclusion,
            cia_impacts=cia_impacts,
        )
        return incident.to_dict()
