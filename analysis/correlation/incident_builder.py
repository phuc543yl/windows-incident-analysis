"""Build stable suspected Incident models from correlation matches."""

from __future__ import annotations

from collections.abc import Iterable

from common.enums import IncidentStatus
from common.exceptions import AnalysisError
from models.finding import Finding
from models.incident import Incident
from models.timeline_event import TimelineEvent
from analysis.correlation.base import CorrelationMatch
from analysis.helpers import deterministic_id, unique_strings


class IncidentBuilder:
    def build(
        self,
        match: CorrelationMatch,
        *,
        findings: Iterable[Finding] = (),
        timeline: Iterable[TimelineEvent] = (),
    ) -> Incident:
        alerts = match.alerts
        case_ids = {alert.case_id for alert in alerts}
        if len(case_ids) != 1:
            raise AnalysisError(
                "Không thể tạo Incident từ nhiều Case."
            )
        alert_ids = tuple(alert.alert_id for alert in alerts)
        finding_ids = unique_strings(
            (
                finding_id
                for alert in alerts
                for finding_id in alert.finding_ids
            )
        )
        known_finding_ids = {
            finding.finding_id for finding in findings
        }
        finding_ids = tuple(
            value
            for value in finding_ids
            if not known_finding_ids or value in known_finding_ids
        )
        source_record_ids = {
            record_id
            for alert in alerts
            for record_id in alert.source_record_ids
        }
        timeline_ids = unique_strings(
            event.timeline_event_id
            for event in timeline
            if source_record_ids.intersection(event.source_record_ids)
        )
        created_at = min(alert.created_at for alert in alerts)
        return Incident(
            case_id=alerts[0].case_id,
            title=match.title,
            description=match.description,
            incident_id=deterministic_id(
                "INC",
                match.incident_type,
                *sorted(alert_ids),
            ),
            status=IncidentStatus.SUSPECTED,
            confidence_score=match.confidence_score,
            alert_ids=unique_strings(alert_ids),
            finding_ids=finding_ids,
            timeline_event_ids=timeline_ids,
            cia_impacts=(),
            created_at=created_at,
            updated_at=created_at,
            recommendations=match.recommendations,
            details={
                "incident_type": match.incident_type,
                **dict(match.details),
            },
        )
