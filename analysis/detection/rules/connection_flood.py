"""Detect a burst of concurrent connections targeting one Windows service."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta
from typing import Any

from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import attribute
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord


class ConnectionFloodRule(BaseRule):
    rule_id = "connection_flood"
    recommendation = (
        "Xác minh địa chỉ nguồn, dịch vụ/port bị nhắm tới, mức sử dụng tài "
        "nguyên và khả năng đáp ứng của dịch vụ trước khi xác nhận DoS."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        threshold = max(2, int(self.parameters.get("threshold", 100)))
        window = timedelta(
            seconds=max(1, int(self.parameters.get("window_seconds", 10)))
        )
        allowed_states = {
            str(value).strip().casefold()
            for value in self.parameters.get(
                "connection_states",
                ("synreceived", "established", "timewait"),
            )
            if str(value).strip()
        }
        groups: dict[
            tuple[str, str, str, int, str],
            list[NormalizedRecord],
        ] = defaultdict(list)

        for record in self.candidates(records):
            observation = _observation(record)
            if observation is None:
                continue
            state = observation["state"]
            if allowed_states and state and state not in allowed_states:
                continue
            groups[
                (
                    observation["source_ip"].casefold(),
                    record.hostname.casefold(),
                    observation["destination_ip"].casefold(),
                    observation["destination_port"],
                    observation["protocol"],
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
                source, hostname, destination, port, protocol = group_key
                states = tuple(
                    sorted(
                        {
                            _observation(record)["state"]
                            for record in episode
                            if _observation(record) is not None
                            and _observation(record)["state"]
                        }
                    )
                )
                alerts.append(
                    self.alert(
                        episode,
                        findings,
                        title="Possible service connection flood",
                        description=(
                            f"Phát hiện {len(episode)} kết nối từ {source} "
                            f"tới {hostname or destination}:{port}/{protocol} "
                            "trong một episode ngắn."
                        ),
                        details={
                            "source_ip": source,
                            "hostname": hostname,
                            "destination_ip": destination,
                            "destination_port": port,
                            "protocol": protocol,
                            "connection_count": len(episode),
                            "window_seconds": window.total_seconds(),
                            "episode_start": episode[0].timestamp,
                            "episode_end": episode[-1].timestamp,
                            "connection_states": states,
                            "observation_timestamp_count": len(
                                {record.timestamp for record in episode}
                            ),
                            "measurement_type": "concurrent_snapshot"
                            if all(
                                record.source_type.casefold() == "live_network"
                                for record in episode
                            )
                            and len({record.timestamp for record in episode}) == 1
                            else "temporal_observations",
                            "baseline_compared": False,
                            "availability_impact_requires_confirmation": True,
                        },
                        indicator_hits=1,
                    )
                )
        return tuple(alerts)


def _observation(record: NormalizedRecord) -> dict[str, Any] | None:
    if record.source_type.casefold() == "live_network":
        source = str(
            attribute(
                record,
                "remote_address",
                default=record.destination_ip,
            )
        ).strip()
        destination = str(
            attribute(
                record,
                "local_address",
                default=record.source_ip,
            )
        ).strip()
        port_value = attribute(record, "local_port", default=None)
    else:
        source = record.source_ip.strip()
        destination = record.destination_ip.strip()
        port_value = attribute(
            record,
            "destination_port",
            "dst_port",
            default=None,
        )

    if not _valid_remote_ip(source):
        return None
    port = _port(port_value)
    if port is None:
        return None
    protocol = _protocol(attribute(record, "protocol", default="tcp"))
    state = str(attribute(record, "state", default="")).strip().casefold()
    return {
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        "protocol": protocol,
        "state": state,
    }


def _valid_remote_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_unspecified or address.is_loopback or address.is_multicast)


def _port(value: Any) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip(), 0)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _protocol(value: Any) -> str:
    text = str(value).strip().casefold()
    return {"6": "tcp", "17": "udp"}.get(text, text or "tcp")


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
