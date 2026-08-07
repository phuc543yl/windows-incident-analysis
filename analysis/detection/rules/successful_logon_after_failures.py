"""Detect an RDP success following related failed logons."""

from __future__ import annotations

from datetime import timedelta

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import (
    integer_attribute,
    source_ip,
    target_user,
)


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
        failure_id = int(
            self.parameters.get("failure_event_id", 4625)
        )
        success_id = int(
            self.parameters.get("success_event_id", 4624)
        )
        logon_type = int(
            self.parameters.get("required_logon_type", 10)
        )
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
        failures = [
            record
            for record in candidates
            if record.event_id == failure_id
        ]
        alerts: list[Alert] = []
        for success in candidates:
            if success.event_id != success_id:
                continue
            if integer_attribute(
                success,
                "logon_type",
                "logontype",
            ) != logon_type:
                continue
            user = target_user(success).casefold()
            address = source_ip(success).casefold()
            related = [
                failure
                for failure in failures
                if success.timestamp - window
                <= failure.timestamp
                <= success.timestamp
                and target_user(failure).casefold() == user
                and source_ip(failure).casefold() == address
            ]
            if len(related) < minimum:
                continue
            alerts.append(
                self.alert(
                    (*related, success),
                    findings,
                    details={
                        "target_user": user,
                        "source_ip": address,
                        "failure_count": len(related),
                        "success_event_id": success_id,
                        "logon_type": logon_type,
                    },
                )
            )
        return tuple(alerts)
