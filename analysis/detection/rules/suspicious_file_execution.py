"""Detect execution evidence from commonly abused paths."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import conceptual_source, text_blob


class SuspiciousFileExecutionRule(BaseRule):
    rule_id = "suspicious_file_execution"
    recommendation = (
        "Thu file, tính hash, kiểm tra chữ ký số và truy vết process "
        "đã thực thi file."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        suspicious = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "suspicious_path_indicators",
                (),
            )
        )
        trusted = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "trusted_system_directories",
                (),
            )
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            source = conceptual_source(record)
            if source == "event_log" and record.event_id not in {
                1,
                4688,
            }:
                continue
            blob = text_blob(record)
            path_hits = tuple(
                value for value in suspicious if value in blob
            )
            if not path_hits or any(value in blob for value in trusted):
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={"suspicious_path_hits": path_hits},
                    indicator_hits=len(path_hits),
                )
            )
        return tuple(alerts)
