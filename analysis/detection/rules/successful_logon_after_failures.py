"""Detect an RDP success following related failed logons."""

from __future__ import annotations

from datetime import timedelta

from analysis.detection.event_identity import group_windows_events
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import (
    integer_attribute,
    source_ip,
    target_user,
)
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord


class SuccessfulLogonAfterFailuresRule(BaseRule):
    rule_id = "successful_logon_after_failures"
    recommendation = (
        "Xác minh chủ tài khoản, địa chỉ nguồn RDP và hoạt động sau "
        "thời điểm đăng nhập thành công."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        candidates = sorted(
            self.candidates(records),
            key=lambda item: item.timestamp,
        )
        failure_id = int(self.parameters.get("failure_event_id", 4625))
        success_id = int(self.parameters.get("success_event_id", 4624))
        logon_type = int(self.parameters.get("required_logon_type", 10))
        minimum = max(
            1,
            int(self.parameters.get("minimum_failures", 5)),
        )
        window = timedelta(
            minutes=max(
                1,
                int(self.parameters.get("window_minutes", 15)),
            )
        )
        failures = [record for record in candidates if record.event_id == failure_id]
        failure_groups = group_windows_events(failures)
        alerts: list[Alert] = []
        successes = [record for record in candidates if record.event_id == success_id]
        for success_group in group_windows_events(successes):
            qualified = [
                record
                for record in success_group
                if integer_attribute(record, "logon_type", "logontype") == logon_type
            ]
            if not qualified:
                continue
            # Prefer the full timestamp over a tool's millisecond truncation.
            success = max(qualified, key=lambda record: record.timestamp)
            user = target_user(success).casefold()
            address = source_ip(success).casefold()
            hostname = success.hostname.strip().casefold()
            if not user or not address or not hostname:
                continue
            related = [
                failure
                for group in failure_groups
                if success.timestamp - window
                <= max(record.timestamp for record in group)
                <= success.timestamp
                and any(
                    target_user(record).casefold() == user
                    and source_ip(record).casefold() == address
                    and record.hostname.strip().casefold() == hostname
                    for record in group
                )
                for failure in group
            ]
            event_count = len(group_windows_events(related))
            if event_count < minimum:
                continue
            alerts.append(
                self.alert(
                    (*related, *success_group),
                    findings,
                    risk_record_count=event_count + 1,
                    details={
                        "target_user": user,
                        "source_ip": address,
                        "hostname": hostname,
                        "failure_count": event_count,
                        "source_record_count": len(related) + len(success_group),
                        "success_event_id": success_id,
                        "logon_type": logon_type,
                    },
                )
            )
        return tuple(alerts)
