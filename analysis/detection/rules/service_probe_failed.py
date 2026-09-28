"""Detect a service availability probe that failed or timed out."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import probe_status, service_name, text_blob


class ServiceProbeFailedRule(BaseRule):
    rule_id = "service_probe_failed"
    recommendation = (
        "Xác minh probe từ máy điều tra, so với baseline thành công và "
        "không gán Availability chỉ vì Event ID."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        failed_states = {
            str(value).casefold()
            for value in self.parameters.get(
                "failed_states",
                ("failed", "timeout", "degraded", "unreachable"),
            )
        }
        alerts: list[Alert] = []
        for record in self.candidates(records):
            status = probe_status(record)
            blob = text_blob(record)
            status_hit = status in failed_states
            text_hit = any(
                token in blob
                for token in (
                    "probe failed",
                    "probe timeout",
                    "service unreachable",
                    "availability degraded",
                )
            )
            if not status_hit and not text_hit:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "service_name": service_name(record),
                        "probe_status": status or "failed",
                        "availability_impact_requires_confirmation": True,
                    },
                    indicator_hits=1,
                )
            )
        return tuple(alerts)
