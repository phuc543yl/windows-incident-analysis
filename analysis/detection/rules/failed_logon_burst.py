from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import source_ip, target_user


class FailedLogonBurstRule(BaseRule):
    rule_id = "failed_logon_burst"
    recommendation = (
        "Kiểm tra địa chỉ nguồn, tài khoản đích và các lần đăng nhập "
        "thành công ngay sau chuỗi thất bại."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", (4625,))
        }
        threshold = max(2, int(self.parameters.get("threshold", 5)))
        window = timedelta(
            minutes=max(
                1,
                int(self.parameters.get("window_minutes", 10)),
            )
        )
        groups: dict[
            tuple[str, str, str],
            list[NormalizedRecord],
        ] = defaultdict(list)
        for record in self.candidates(records):
            if record.event_id in event_ids:
                groups[
                    (
                        target_user(record).casefold(),
                        source_ip(record).casefold(),
                        record.hostname.casefold(),
                    )
                ].append(record)

        alerts: list[Alert] = []
        for group_key, grouped in groups.items():
            ordered = sorted(grouped, key=lambda item: item.timestamp)
            episodes: list[list[NormalizedRecord]] = []
            for record in ordered:
                if (
                    not episodes
                    or record.timestamp - episodes[-1][-1].timestamp > window
                ):
                    episodes.append([record])
                else:
                    episodes[-1].append(record)
            for episode in episodes:
                if len(episode) < threshold:
                    continue
                if not _contains_threshold_window(episode, threshold, window):
                    continue
                alerts.append(
                    self.alert(
                        episode,
                        findings,
                        details={
                            "target_user": group_key[0],
                            "source_ip": group_key[1],
                            "hostname": group_key[2],
                            "failure_count": len(episode),
                            "window_minutes": window.total_seconds() / 60,
                            "episode_start": episode[0].timestamp,
                            "episode_end": episode[-1].timestamp,
                        },
                    )
                )
        return tuple(alerts)


def _contains_threshold_window(
    records: list[NormalizedRecord],
    threshold: int,
    window: timedelta,
) -> bool:
    start = 0
    for end, record in enumerate(records):
        while record.timestamp - records[start].timestamp > window:
            start += 1
        if end - start + 1 >= threshold:
            return True
    return False