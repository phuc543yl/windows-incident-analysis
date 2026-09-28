"""Build a short investigation story from correlated incidents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models.alert import Alert
from models.incident import Incident
from models.timeline_event import TimelineEvent


@dataclass(frozen=True, slots=True)
class StoryMilestone:
    order: int
    timestamp: str
    title: str
    summary: str
    incident_id: str
    alert_ids: tuple[str, ...]
    timeline_event_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "timestamp": self.timestamp,
            "title": self.title,
            "summary": self.summary,
            "incident_id": self.incident_id,
            "alert_ids": list(self.alert_ids),
            "timeline_event_id": self.timeline_event_id,
        }


class StoryBuilder:
    def build(
        self,
        incidents: tuple[Incident, ...],
        alerts: tuple[Alert, ...] = (),
        timeline: tuple[TimelineEvent, ...] = (),
        *,
        limit: int = 8,
    ) -> tuple[StoryMilestone, ...]:
        alerts_by_id = {alert.alert_id: alert for alert in alerts}
        events_by_id = {
            event.timeline_event_id: event for event in timeline
        }
        milestones: list[StoryMilestone] = []
        for incident in incidents:
            related_alerts = tuple(
                alerts_by_id[alert_id]
                for alert_id in incident.alert_ids
                if alert_id in alerts_by_id
            )
            if related_alerts:
                for alert in related_alerts:
                    event = _nearest_event(alert, timeline, events_by_id)
                    milestones.append(
                        StoryMilestone(
                            order=0,
                            timestamp=_iso(alert.created_at),
                            title=alert.title,
                            summary=alert.description,
                            incident_id=incident.incident_id,
                            alert_ids=(alert.alert_id,),
                            timeline_event_id=(
                                event.timeline_event_id if event else ""
                            ),
                        )
                    )
            else:
                milestones.append(
                    StoryMilestone(
                        order=0,
                        timestamp=_iso(incident.created_at),
                        title=incident.title,
                        summary=incident.description,
                        incident_id=incident.incident_id,
                        alert_ids=incident.alert_ids,
                    )
                )
        ordered = sorted(
            milestones,
            key=lambda item: (item.timestamp, item.title),
        )
        trimmed = ordered[: max(1, limit)] if ordered else ()
        return tuple(
            StoryMilestone(
                order=index,
                timestamp=item.timestamp,
                title=item.title,
                summary=item.summary,
                incident_id=item.incident_id,
                alert_ids=item.alert_ids,
                timeline_event_id=item.timeline_event_id,
            )
            for index, item in enumerate(trimmed, start=1)
        )


def _nearest_event(
    alert: Alert,
    timeline: tuple[TimelineEvent, ...],
    events_by_id,
) -> TimelineEvent | None:
    for event_id in getattr(alert, "timeline_event_ids", ()):
        if event_id in events_by_id:
            return events_by_id[event_id]
    source_ids = set(alert.source_record_ids)
    for event in timeline:
        if source_ids.intersection(event.source_record_ids):
            return event
    return None


def _iso(value) -> str:
    text = getattr(value, "isoformat", None)
    if callable(text):
        rendered = value.isoformat().replace("+00:00", "Z")
        return rendered if rendered.endswith("Z") else f"{rendered}Z"
    return str(value)
