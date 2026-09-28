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
        probes = [
            alert
            for alert in alerts
            if alert.rule_id == "service_probe_failed"
        ]
        matches: list[CorrelationMatch] = []
        for stopped in alerts:
            if stopped.rule_id != "service_stopped":
                continue
            name = str(
                stopped.details.get("service_name", "")
            ).casefold()
            related_changes = [
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
            related_probes = [
                alert
                for alert in probes
                if abs(
                    (alert.created_at - stopped.created_at).total_seconds()
                )
                <= timedelta(minutes=60).total_seconds()
                and (
                    not name
                    or str(
                        alert.details.get("service_name", "")
                    ).casefold()
                    in {name, ""}
                )
            ]
            confidence = 0.68
            if related_changes:
                confidence += 0.10
            if related_probes:
                confidence += 0.10
            matches.append(
                CorrelationMatch(
                    incident_type="service_disruption",
                    title="Nghi vấn gián đoạn dịch vụ Windows",
                    description=(
                        "Dịch vụ chuyển sang trạng thái dừng và cần xác "
                        "minh tính hợp lệ cùng ảnh hưởng Availability."
                    ),
                    alerts=tuple((stopped, *related_changes, *related_probes)),
                    confidence_score=min(0.95, confidence),
                    recommendations=(
                        "Xác minh thay đổi với chủ hệ thống.",
                        "Đánh giá downtime và chức năng bị ảnh hưởng.",
                    ),
                    details={
                        "service_name": name,
                        "probe_supported": bool(related_probes),
                        "availability_impact_requires_confirmation": True,
                    },
                )
            )
        return tuple(matches)
