"""Create a suspected log-tampering incident from clear-log Alerts."""

from __future__ import annotations

from datetime import timedelta

from analysis.correlation.base import CorrelationMatch
from analysis.correlation.entities import related_endpoint
from models.alert import Alert

_COMPANION_RULES = {
    "suspicious_powershell",
    "powershell_scriptblock_suspicious",
    "event_log_service_shutdown",
}


class LogTamperingCorrelation:
    def correlate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[CorrelationMatch, ...]:
        companions = [alert for alert in alerts if alert.rule_id in _COMPANION_RULES]
        matches: list[CorrelationMatch] = []
        for alert in alerts:
            if alert.rule_id != "security_log_cleared":
                continue
            related = tuple(
                companion
                for companion in companions
                if abs((companion.created_at - alert.created_at).total_seconds())
                <= timedelta(minutes=30).total_seconds()
                and related_endpoint(alert, companion)
            )
            matches.append(
                CorrelationMatch(
                    incident_type="log_tampering",
                    title="Nghi vấn Windows Event Log bị xóa",
                    description=(
                        "Phát hiện dấu hiệu xóa Security hoặc System Event Log."
                    ),
                    alerts=(alert, *related),
                    confidence_score=0.92 if related else 0.78,
                    recommendations=(
                        "Bảo toàn EVTX còn lại và xác định actor.",
                        "Dựng timeline hoạt động trước thời điểm log bị xóa.",
                    ),
                    details={
                        "event_id": alert.details.get("event_id"),
                        "companion_rule_ids": tuple(item.rule_id for item in related),
                        "integrity_impact_requires_confirmation": True,
                    },
                )
            )
        return tuple(matches)
