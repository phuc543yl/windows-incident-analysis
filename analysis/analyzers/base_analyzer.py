"""Base contract for modules that produce contextual Findings."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from common.enums import FindingSeverity
from common.exceptions import AnalysisError
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.helpers import deterministic_id


class BaseAnalyzer(ABC):
    analyzer_id: str

    def analyze(
        self,
        records: Iterable[NormalizedRecord],
    ) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        case_id: str | None = None
        for record in records:
            if not isinstance(record, NormalizedRecord):
                raise TypeError("Analyzer chỉ nhận NormalizedRecord.")
            if case_id is None:
                case_id = record.case_id
            elif record.case_id != case_id:
                raise AnalysisError(
                    "Analyzer không thể xử lý nhiều Case."
                )
            finding = self.analyze_record(record)
            if finding is not None:
                findings.append(finding)
        return tuple(findings)

    @abstractmethod
    def analyze_record(
        self,
        record: NormalizedRecord,
    ) -> Finding | None:
        """Return a noteworthy contextual observation or None."""

    def finding(
        self,
        record: NormalizedRecord,
        *,
        title: str,
        description: str,
        severity: FindingSeverity | str,
        confidence_score: float,
        mitre_techniques: tuple[str, ...] = (),
        details: dict | None = None,
    ) -> Finding:
        return Finding(
            case_id=record.case_id,
            title=title,
            description=description,
            severity=severity,
            finding_id=deterministic_id(
                "FIND",
                self.analyzer_id,
                record.record_id,
            ),
            analyzer_id=self.analyzer_id,
            source_record_ids=(record.record_id,),
            mitre_techniques=mitre_techniques,
            confidence_score=confidence_score,
            created_at=record.timestamp,
            details=dict(details or {}),
        )
