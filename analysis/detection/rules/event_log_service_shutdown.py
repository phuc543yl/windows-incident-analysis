"""Detect Event Log service shutdown (Event ID 1100)."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule


class EventLogServiceShutdownRule(BaseRule):
    rule_id = "event_log_service_shutdown"
    recommendation = (
        "Đối chiếu Event 1100 với 1102/104 và xác định actor trước khi "
        "kết luận anti-forensics."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", (1100,))
        }
        alerts: list[Alert] = []
        for record in self.candidates(records):
            if record.event_id not in event_ids:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "event_id": record.event_id,
                        "hostname": record.hostname,
                        "user": record.user,
                    },
                )
            )
        return tuple(alerts)
