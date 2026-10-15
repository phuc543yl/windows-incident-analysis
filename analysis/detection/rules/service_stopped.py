from __future__ import annotations

from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import (
    attribute,
    integer_attribute,
    maintenance_authorization,
    service_name,
    text_blob,
)
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord


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
        event_ids = {int(value) for value in self.parameters.get("event_ids", (7036,))}
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
        require_unauthorized = bool(
            self.parameters.get("require_unauthorized_context", True)
        )
        minimum_downtime = max(
            0,
            int(self.parameters.get("minimum_downtime_seconds", 0) or 0),
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            name = service_name(record)
            if name.casefold() in allowlist:
                continue
            approval = maintenance_authorization(record)
            if require_unauthorized and approval is not False:
                continue
            downtime = integer_attribute(
                record,
                "downtime_seconds",
                "outage_seconds",
            )
            if minimum_downtime and (downtime is None or downtime < minimum_downtime):
                continue
            blob = text_blob(record)
            state = (
                str(attribute(record, "State", "status", "param2")).strip().casefold()
            )
            state_hits = tuple(
                value
                for value in states
                if (state == value if state else value in blob)
            )
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
                        "unauthorized_context_required": require_unauthorized,
                        "authorized_maintenance": approval,
                        "downtime_seconds": downtime,
                    },
                    indicator_hits=len(state_hits),
                )
            )
        return tuple(alerts)
