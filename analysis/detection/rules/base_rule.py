"""Base class for configured detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from common.enums import FindingSeverity
from common.exceptions import AnalysisError
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.risk_engine import RiskEngine
from analysis.helpers import (
    deterministic_id,
    source_allowed,
    unique_strings,
)


class BaseRule(ABC):
    rule_id: str
    recommendation = "Xem xét record nguồn và xác minh với chủ hệ thống."

    def __init__(
        self,
        config: dict[str, Any],
        *,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        if config.get("id") != self.rule_id:
            raise AnalysisError(
                f"Config không dành cho rule {self.rule_id}."
            )
        self.config = dict(config)
        self.name = _required_text(config.get("name"), "name")
        self.description = _required_text(
            config.get("description"),
            "description",
        )
        self.enabled = bool(config.get("enabled", True))
        self.severity = FindingSeverity(
            str(config.get("severity", "medium"))
        )
        self.base_risk_score = float(config.get("risk_score", 50))
        self.source_types = tuple(config.get("source_types", ()))
        self.mitre_techniques = tuple(
            str(value)
            for value in config.get("mitre_techniques", ())
        )
        parameters = config.get("parameters", {})
        if not isinstance(parameters, dict):
            raise AnalysisError(
                f"parameters của {self.rule_id} phải là object."
            )
        self.parameters = dict(parameters)
        self.risk_engine = risk_engine or RiskEngine()

    def candidates(
        self,
        records: Iterable[NormalizedRecord],
    ) -> tuple[NormalizedRecord, ...]:
        return tuple(
            record
            for record in records
            if source_allowed(record, self.source_types)
        )

    @abstractmethod
    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        """Evaluate records and return Alerts."""

    def alert(
        self,
        records: Iterable[NormalizedRecord],
        findings: tuple[Finding, ...],
        *,
        title: str | None = None,
        description: str | None = None,
        details: dict[str, Any] | None = None,
        indicator_hits: int = 0,
    ) -> Alert:
        source_records = tuple(records)
        if not source_records:
            raise AnalysisError(
                f"Rule {self.rule_id} không thể tạo Alert rỗng."
            )
        case_ids = {record.case_id for record in source_records}
        if len(case_ids) != 1:
            raise AnalysisError("Alert không thể chứa nhiều Case.")
        source_ids = tuple(record.record_id for record in source_records)
        source_id_set = set(source_ids)
        linked_findings = tuple(
            finding
            for finding in findings
            if source_id_set.intersection(finding.source_record_ids)
        )
        alert_id = deterministic_id(
            "ALERT",
            self.rule_id,
            *sorted(source_ids),
        )
        return Alert(
            case_id=source_records[0].case_id,
            rule_id=self.rule_id,
            title=title or self.name,
            description=description or self.description,
            severity=self.severity,
            risk_score=self.risk_engine.calculate(
                self.base_risk_score,
                self.severity,
                record_count=len(source_records),
                indicator_hits=indicator_hits,
            ),
            alert_id=alert_id,
            finding_ids=unique_strings(
                finding.finding_id for finding in linked_findings
            ),
            source_record_ids=unique_strings(source_ids),
            evidence_item_ids=unique_strings(
                evidence_id
                for finding in linked_findings
                for evidence_id in finding.evidence_item_ids
            ),
            mitre_techniques=self.mitre_techniques,
            created_at=max(
                record.timestamp for record in source_records
            ),
            recommendation=self.recommendation,
            details=dict(details or {}),
        )


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AnalysisError(f"Rule thiếu {field_name}.")
    return value.strip()
