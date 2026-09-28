"""Create context Findings for notable network connections."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable

from common.enums import ArtifactType, FindingSeverity
from common.exceptions import AnalysisError
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer
from analysis.helpers import attribute

_BURST_THRESHOLD = 20


class NetworkAnalyzer(BaseAnalyzer):
    analyzer_id = "network_analyzer"

    def analyze(
        self,
        records: Iterable[NormalizedRecord],
    ) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        case_id: str | None = None
        internal_groups: dict[tuple[str, int], list[NormalizedRecord]] = (
            defaultdict(list)
        )
        for record in records:
            if not isinstance(record, NormalizedRecord):
                raise TypeError("Analyzer chỉ nhận NormalizedRecord.")
            if case_id is None:
                case_id = record.case_id
            elif record.case_id != case_id:
                raise AnalysisError("Analyzer không thể xử lý nhiều Case.")
            finding = self.analyze_record(record)
            if finding is not None:
                findings.append(finding)
            grouped = _internal_group_key(record)
            if grouped is not None:
                internal_groups[grouped].append(record)
        for (hostname, port), grouped_records in internal_groups.items():
            if len(grouped_records) < _BURST_THRESHOLD:
                continue
            first = grouped_records[0]
            findings.append(
                self.finding(
                    first,
                    title="Nhiều kết nối nội bộ tới cùng dịch vụ",
                    description=(
                        f"{len(grouped_records)} kết nối nội bộ tới "
                        f"{hostname}:{port} cần đối chiếu baseline."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    confidence_score=0.7,
                    mitre_techniques=("T1499.002",),
                    details={
                        "scope": "internal",
                        "hostname": hostname,
                        "destination_port": port,
                        "connection_count": len(grouped_records),
                    },
                )
            )
        return tuple(findings)

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if record.artifact_type is not ArtifactType.NETWORK:
            return None
        address_text = (record.destination_ip or record.source_ip or "").strip()
        if not address_text:
            return None
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            return None
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return None
        if address.is_private:
            return None
        return self.finding(
            record,
            title="Kết nối đến địa chỉ IP bên ngoài",
            description=record.summary,
            severity=FindingSeverity.INFO,
            confidence_score=0.6,
            details={
                "scope": "external",
                "destination_ip": address_text,
                "process_id": record.process_id,
            },
        )


def _internal_group_key(
    record: NormalizedRecord,
) -> tuple[str, int] | None:
    if record.artifact_type is not ArtifactType.NETWORK:
        return None
    remote = str(
        attribute(
            record,
            "remote_address",
            default=record.destination_ip or record.source_ip,
        )
    ).strip()
    try:
        address = ipaddress.ip_address(remote)
    except ValueError:
        return None
    if not address.is_private or address.is_loopback:
        return None
    port_value = attribute(
        record,
        "local_port",
        "destination_port",
        "dst_port",
        default=None,
    )
    if port_value in (None, "") or isinstance(port_value, bool):
        return None
    try:
        port = int(str(port_value).strip(), 0)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return (record.hostname.casefold() or "unknown", port)
