from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import service_name, text_blob


class ServiceStoppedRule(BaseRule):
    rule_id = "service_stopped"
    recommendation = (
        "Xác minh thay đổi có được phê duyệt không, thời gian downtime "
        "và ảnh hưởng Availability."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", (7036,))
        }
        states = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "stopped_state_values",
                ("stopped",),
            )
        )
        allowlist = {
            str(value).casefold()
            for value in self.parameters.get("service_allowlist", ())
        }
        alerts: list[Alert] = []
        for record in self.candidates(records):
            name = service_name(record)
            if name.casefold() in allowlist:
                continue
            blob = text_blob(record)
            state_hits = tuple(value for value in states if value in blob)
            if record.event_id not in event_ids:
                continue
            if not state_hits:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "service_name": name,
                        "state_hits": state_hits,
                        "unauthorized_context_required": bool(
                            self.parameters.get(
                                "require_unauthorized_context",
                                True,
                            )
                        ),
                    },
                    indicator_hits=len(state_hits),
                )
            )
        return tuple(alerts)