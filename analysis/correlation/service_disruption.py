"""Correlate stopped service and nearby configuration changes."""

from __future__ import annotations

from datetime import timedelta

from models.alert import Alert
from analysis.correlation.base import CorrelationMatch


class ServiceDisruptionCorrelation:
    def correlate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[CorrelationMatch, ...]:
        changes = [
            alert
            for alert in alerts
            if alert.rule_id == "service_configuration_changed"
        ]
        matches: list[CorrelationMatch] = []
        for stopped in alerts:
            if stopped.rule_id != "service_stopped":
                continue
            name = str(
                stopped.details.get("service_name", "")
            ).casefold()
            related = [
                alert
                for alert in changes
                if abs(
                    (alert.created_at - stopped.created_at).total_seconds()
                )
                <= timedelta(minutes=60).total_seconds()
                and (
                    not name
                    or str(
                        alert.details.get("service_name", "")
                    ).casefold()
                    == name
                )
            ]
            matches.append(
                CorrelationMatch(
                    incident_type="service_disruption",
                    title="Nghi vấn gián đoạn dịch vụ Windows",
                    description=(
                        "Dịch vụ chuyển sang trạng thái dừng và cần xác "
                        "minh tính hợp lệ cùng ảnh hưởng Availability."
                    ),
                    alerts=tuple((stopped, *related)),
                    confidence_score=0.78 if related else 0.68,
                    recommendations=(
                        "Xác minh thay đổi với chủ hệ thống.",
                        "Đánh giá downtime và chức năng bị ảnh hưởng.",
                    ),
                    details={"service_name": name},
                )
            )
        return tuple(matches)
