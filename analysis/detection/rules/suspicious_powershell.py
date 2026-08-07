"""Detect suspicious PowerShell command indicators."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import text_blob


class SuspiciousPowerShellRule(BaseRule):
    rule_id = "suspicious_powershell"
    recommendation = (
        "Giải mã command, kiểm tra parent process, script block và kết nối "
        "mạng liên quan."
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
        names = {
            str(value).casefold()
            for value in self.parameters.get("process_names", ())
        }
        indicators = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "case_insensitive_indicators",
                (),
            )
        )
        minimum_hits = max(
            1,
            int(self.parameters.get("minimum_indicator_hits", 1)),
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            if (
                record.process_name.casefold() not in names
                and record.event_id not in event_ids
                and "powershell" not in text_blob(record)
            ):
                continue
            blob = text_blob(record)
            hits = tuple(
                indicator for indicator in indicators if indicator in blob
            )
            if len(hits) < minimum_hits:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "indicator_hits": hits,
                        "process_name": record.process_name,
                        "process_id": record.process_id,
                        "parent_process_id": record.parent_process_id,
                    },
                    indicator_hits=len(hits),
                )
            )
        return tuple(alerts)
