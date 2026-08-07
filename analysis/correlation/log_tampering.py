"""Create a suspected log-tampering incident from clear-log Alerts."""

from __future__ import annotations

from models.alert import Alert
from analysis.correlation.base import CorrelationMatch


class LogTamperingCorrelation:
    def correlate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[CorrelationMatch, ...]:
        return tuple(
            CorrelationMatch(
                incident_type="log_tampering",
                title="Nghi vấn Windows Event Log bị xóa",
                description=(
                    "Phát hiện dấu hiệu xóa Security hoặc System Event Log."
                ),
                alerts=(alert,),
                confidence_score=0.9,
                recommendations=(
                    "Bảo toàn EVTX còn lại và xác định actor.",
                    "Dựng timeline hoạt động trước thời điểm log bị xóa.",
                ),
                details={"event_id": alert.details.get("event_id")},
            )
            for alert in alerts
            if alert.rule_id == "security_log_cleared"
        )
