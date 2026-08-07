"""Detect Windows Event Log clearing."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import text_blob


class SecurityLogClearedRule(BaseRule):
    rule_id = "security_log_cleared"
    recommendation = (
        "Xác định actor, kiểm tra log còn lại và dựng timeline hoạt động "
        "trước thời điểm log bị xóa."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", ())
        }
        commands = tuple(
            str(value).casefold()
            for value in self.parameters.get("command_indicators", ())
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            blob = text_blob(record)
            hits = tuple(value for value in commands if value in blob)
            if record.event_id not in event_ids and not hits:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "event_id": record.event_id,
                        "command_hits": hits,
                        "actor_review_required": bool(
                            self.parameters.get(
                                "require_actor_review",
                                True,
                            )
                        ),
                    },
                    indicator_hits=len(hits),
                )
            )
        return tuple(alerts)
