"""Run incident-pattern correlations over Alerts."""

from __future__ import annotations

from collections.abc import Iterable

from common.exceptions import AnalysisError
from models.alert import Alert
from models.finding import Finding
from models.incident import Incident
from models.timeline_event import TimelineEvent
from analysis.correlation.incident_builder import IncidentBuilder
from analysis.correlation.profiles import (
    ALL_CORRELATORS,
    correlators_for_profile,
)


class CorrelationEngine:
    def __init__(
        self,
        *,
        correlators=ALL_CORRELATORS,
        incident_builder: IncidentBuilder | None = None,
    ) -> None:
        self.correlators = tuple(correlators)
        self.incident_builder = incident_builder or IncidentBuilder()

    def correlate(
        self,
        alerts: Iterable[Alert],
        *,
        findings: Iterable[Finding] = (),
        timeline: Iterable[TimelineEvent] = (),
        profile: str | None = None,
    ) -> tuple[Incident, ...]:
        alert_items = tuple(alerts)
        finding_items = tuple(findings)
        timeline_items = tuple(timeline)
        case_ids = {alert.case_id for alert in alert_items}
        if len(case_ids) > 1:
            raise AnalysisError(
                "CorrelationEngine không thể xử lý nhiều Case."
            )
        correlators = (
            correlators_for_profile(profile)
            if profile is not None
            else self.correlators
        )
        incidents: list[Incident] = []
        seen: set[str] = set()
        for correlator in correlators:
            for match in correlator.correlate(alert_items):
                incident = self.incident_builder.build(
                    match,
                    findings=finding_items,
                    timeline=timeline_items,
                )
                if incident.incident_id in seen:
                    continue
                seen.add(incident.incident_id)
                incidents.append(incident)
        return tuple(
            sorted(
                incidents,
                key=lambda item: (
                    item.created_at,
                    item.incident_id,
                ),
            )
        )
