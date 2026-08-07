"""Create context Findings for external network connections."""

from __future__ import annotations

import ipaddress

from common.enums import ArtifactType, FindingSeverity
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.analyzers.base_analyzer import BaseAnalyzer


class NetworkAnalyzer(BaseAnalyzer):
    analyzer_id = "network_analyzer"

    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        if (
            record.artifact_type is not ArtifactType.NETWORK
            or not record.destination_ip
        ):
            return None
        try:
            address = ipaddress.ip_address(record.destination_ip)
        except ValueError:
            return None
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        ):
            return None
        return self.finding(
            record,
            title="Kết nối đến địa chỉ IP bên ngoài",
            description=record.summary,
            severity=FindingSeverity.INFO,
            confidence_score=0.6,
            details={
                "destination_ip": record.destination_ip,
                "process_id": record.process_id,
            },
        )
