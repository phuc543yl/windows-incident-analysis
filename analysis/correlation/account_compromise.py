"""Correlate failed logons and a related RDP success."""

from __future__ import annotations

from datetime import timedelta

from analysis.correlation.base import CorrelationMatch
from analysis.correlation.entities import related_endpoint
from models.alert import Alert


class AccountCompromiseCorrelation:
    def correlate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[CorrelationMatch, ...]:
        failures = [alert for alert in alerts if alert.rule_id == "failed_logon_burst"]
        matches: list[CorrelationMatch] = []
        for success in alerts:
            if success.rule_id != "successful_logon_after_failures":
                continue
            user = str(success.details.get("target_user", "")).casefold()
            address = str(success.details.get("source_ip", "")).casefold()
            related = [
                failure
                for failure in failures
                if success.created_at - timedelta(minutes=30)
                <= failure.created_at
                <= success.created_at
                and str(failure.details.get("target_user", "")).casefold() == user
                and str(failure.details.get("source_ip", "")).casefold() == address
                and related_endpoint(success, failure)
            ]
            matched_alerts = tuple((*related, success))
            matches.append(
                CorrelationMatch(
                    incident_type="account_compromise",
                    title="Nghi vấn tài khoản bị xâm nhập qua RDP",
                    description=(
                        "Đăng nhập RDP thành công xuất hiện sau chuỗi "
                        "đăng nhập thất bại liên quan."
                    ),
                    alerts=matched_alerts,
                    confidence_score=0.85,
                    recommendations=(
                        "Khóa hoặc reset thông tin xác thực nếu được xác nhận.",
                        "Kiểm tra hoạt động sau đăng nhập của tài khoản.",
                    ),
                    details={
                        "target_user": user,
                        "source_ip": address,
                    },
                )
            )
        return tuple(matches)
