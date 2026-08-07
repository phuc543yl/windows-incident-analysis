"""Detect Registry Run and RunOnce modifications."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import text_blob


class RegistryAutorunChangeRule(BaseRule):
    rule_id = "registry_autorun_change"
    recommendation = (
        "Xác minh Registry value, binary đích, chữ ký số và thời điểm tạo."
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
        keys = tuple(
            str(value).casefold()
            for value in self.parameters.get("key_indicators", ())
        )
        paths = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "suspicious_path_indicators",
                (),
            )
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            blob = text_blob(record)
            key_hits = tuple(value for value in keys if value in blob)
            if not key_hits:
                continue
            if (
                record.event_id is not None
                and record.event_id not in event_ids
                and record.artifact_type.value != "registry"
            ):
                continue
            path_hits = tuple(value for value in paths if value in blob)
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "key_hits": key_hits,
                        "suspicious_path_hits": path_hits,
                    },
                    indicator_hits=len(key_hits) + len(path_hits),
                )
            )
        return tuple(alerts)
