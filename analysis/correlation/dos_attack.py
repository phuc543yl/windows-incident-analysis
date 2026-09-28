"""Build a suspected DoS incident from a service connection-flood alert."""

from __future__ import annotations

from datetime import timedelta

from models.alert import Alert
from analysis.correlation.base import CorrelationMatch


class DosAttackCorrelation:
    def correlate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[CorrelationMatch, ...]:
        probes = [
            alert
            for alert in alerts
            if alert.rule_id == "service_probe_failed"
        ]
        matches: list[CorrelationMatch] = []
        for alert in alerts:
            if alert.rule_id != "connection_flood":
                continue
            related = tuple(
                probe
                for probe in probes
                if abs(
                    (probe.created_at - alert.created_at).total_seconds()
                )
                <= timedelta(minutes=15).total_seconds()
            )
            matches.append(
                CorrelationMatch(
                    incident_type="dos_attack",
                    title="Nghi vấn DoS vào dịch vụ Windows",
                    description=(
                        "Một nguồn tạo lượng lớn kết nối tới cùng dịch vụ "
                        "trong thời gian ngắn. Cần đối chiếu Ground Truth "
                        "để xác nhận ảnh hưởng Availability."
                    ),
                    alerts=(alert, *related),
                    confidence_score=0.86 if related else 0.72,
                    recommendations=(
                        "Xác minh service response/timeout trong khoảng cảnh báo.",
                        "Đối chiếu CPU, memory, network và log ứng dụng nếu có.",
                        "Kiểm tra nguồn phát và baseline trước khi chặn địa chỉ.",
                    ),
                    details={
                        "source_ip": alert.details.get("source_ip", ""),
                        "hostname": alert.details.get("hostname", ""),
                        "destination_ip": alert.details.get(
                            "destination_ip", ""
                        ),
                        "destination_port": alert.details.get(
                            "destination_port"
                        ),
                        "connection_count": alert.details.get(
                            "connection_count", 0
                        ),
                        "probe_supported": bool(related),
                        "availability_impact_requires_confirmation": True,
                    },
                )
            )
        return tuple(matches)
