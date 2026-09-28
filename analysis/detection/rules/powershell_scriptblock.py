"""Detect suspicious PowerShell Script Block Logging (Event 4104)."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import text_blob


class PowerShellScriptBlockRule(BaseRule):
    rule_id = "powershell_scriptblock_suspicious"
    recommendation = (
        "Đọc ScriptBlockText, xác minh ngữ cảnh quản trị và parent process."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", (4104,))
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
            if record.event_id not in event_ids:
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
                        "event_id": record.event_id,
                        "indicator_hits": hits,
                    },
                    indicator_hits=len(hits),
                )
            )
        return tuple(alerts)
