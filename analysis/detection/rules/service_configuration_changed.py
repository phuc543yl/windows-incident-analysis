"""Detect service installation and configuration changes."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import (
    conceptual_source,
    service_name,
    text_blob,
)


class ServiceConfigurationChangedRule(BaseRule):
    rule_id = "service_configuration_changed"
    recommendation = (
        "Kiểm tra binary path, startup type, tài khoản dịch vụ và "
        "thời điểm cài đặt/thay đổi."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", (7040, 7045))
        }
        paths = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "suspicious_binary_path_indicators",
                (),
            )
        )
        review_start = bool(
            self.parameters.get("review_start_type_changes", True)
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            blob = text_blob(record)
            source = conceptual_source(record)
            path_hits = tuple(value for value in paths if value in blob)
            is_event = record.event_id in event_ids
            is_service_source = source == "service"
            is_service_registry = (
                source == "registry"
                and "/system/currentcontrolset/services/" in blob
            )
            if not (
                is_event
                or is_service_source
                or is_service_registry
            ):
                continue
            start_change = review_start and any(
                value in blob
                for value in (
                    "startup type",
                    "start type",
                    "starttype",
                )
            )
            if not (
                is_event
                or path_hits
                or start_change
            ):
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "service_name": service_name(record),
                        "suspicious_path_hits": path_hits,
                        "event_id": record.event_id,
                    },
                    indicator_hits=len(path_hits),
                )
            )
        return tuple(alerts)
