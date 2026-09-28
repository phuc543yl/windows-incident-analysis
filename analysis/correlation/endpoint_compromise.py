"""Correlate multiple execution and persistence Alerts."""

from __future__ import annotations

from datetime import timedelta

from models.alert import Alert
from analysis.correlation.base import CorrelationMatch

_ENDPOINT_RULES = {
    "suspicious_powershell",
    "powershell_scriptblock_suspicious",
    "registry_autorun_change",
    "scheduled_task_created",
    "suspicious_file_execution",
    "service_configuration_changed",
    "file_integrity_change",
}


class EndpointCompromiseCorrelation:
    def correlate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[CorrelationMatch, ...]:
        candidates = sorted(
            (
                alert
                for alert in alerts
                if alert.rule_id in _ENDPOINT_RULES
            ),
            key=lambda item: item.created_at,
        )
        matches: list[CorrelationMatch] = []
        consumed: set[str] = set()
        for index, first in enumerate(candidates):
            if first.alert_id in consumed:
                continue
            window = tuple(
                alert
                for alert in candidates[index:]
                if alert.created_at - first.created_at
                <= timedelta(minutes=30)
            )
            rule_ids = {alert.rule_id for alert in window}
            if len(rule_ids) < 2:
                continue
            shared = _shared_entities(window)
            consumed.update(alert.alert_id for alert in window)
            matches.append(
                CorrelationMatch(
                    incident_type="endpoint_compromise",
                    title="Nghi vấn endpoint bị xâm nhập",
                    description=(
                        "Nhiều dấu hiệu thực thi hoặc persistence xuất "
                        "hiện gần nhau trong cùng Case."
                    ),
                    alerts=window,
                    confidence_score=min(
                        0.95,
                        0.65 + 0.08 * len(rule_ids) + (0.05 if shared else 0),
                    ),
                    recommendations=(
                        "Cô lập endpoint nếu chuyên viên xác nhận.",
                        "Thu file liên quan và mở rộng timeline tiến trình.",
                    ),
                    details={
                        "rule_ids": tuple(sorted(rule_ids)),
                        "shared_entities": shared,
                    },
                )
            )
        return tuple(matches)


def _shared_entities(alerts: tuple[Alert, ...]) -> tuple[str, ...]:
    values: dict[str, set[str]] = {}
    for alert in alerts:
        for key in ("target_user", "source_ip", "hostname", "file_path"):
            value = str(alert.details.get(key, "")).strip().casefold()
            if not value:
                continue
            values.setdefault(key, set()).add(value)
    return tuple(
        sorted(
            f"{key}:{next(iter(items))}"
            for key, items in values.items()
            if len(items) == 1
        )
    )
