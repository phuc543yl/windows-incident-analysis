"""Run analyzers, detection rules, correlation, and persist Case results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.enums import CIAImpact, IncidentStatus
from common.exceptions import AnalysisError, JsonFileError, ProcessingError
from common.json_utils import read_json_object, write_json
from common.time_utils import utc_now
from models.alert import Alert
from models.finding import Finding
from models.incident import Incident
from models.normalized_record import NormalizedRecord
from models.timeline_event import TimelineEvent
from processing.processing_pipeline import ProcessingPipeline
from processing.timeline_builder import TimelineBuilder
from analysis.analyzers import DEFAULT_ANALYZERS, BaseAnalyzer
from analysis.correlation import CorrelationEngine
from analysis.detection import RuleEngine
from analysis.history_service import AnalysisHistoryService

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    case_id: str
    record_count: int
    finding_count: int
    alert_count: int
    incident_count: int
    findings: tuple[Finding, ...]
    alerts: tuple[Alert, ...]
    incidents: tuple[Incident, ...]
    findings_path: Path | None = None
    alerts_path: Path | None = None
    incidents_path: Path | None = None
    previous_version_path: Path | None = None

    def __post_init__(self) -> None:
        if self.finding_count != len(self.findings):
            raise ValueError("finding_count không khớp findings.")
        if self.alert_count != len(self.alerts):
            raise ValueError("alert_count không khớp alerts.")
        if self.incident_count != len(self.incidents):
            raise ValueError("incident_count không khớp incidents.")


class AnalysisService:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        analyzers: Iterable[BaseAnalyzer] = DEFAULT_ANALYZERS,
        rule_engine: RuleEngine | None = None,
        correlation_engine: CorrelationEngine | None = None,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.analyzers = tuple(analyzers)
        self.rule_engine = rule_engine or RuleEngine(
            self.repository.project
        )
        self.correlation_engine = (
            correlation_engine or CorrelationEngine()
        )
        self.actor = actor.strip() or "analyst"

    def analyze(
        self,
        *,
        case_id: str,
        records: Iterable[NormalizedRecord] | None = None,
        timeline: Iterable[TimelineEvent] | None = None,
        persist: bool = True,
    ) -> AnalysisResult:
        case = self.repository.require_open(case_id)
        plan = self.repository.load_collection_plan(case.case_id)
        pipeline = ProcessingPipeline(self.repository.project)
        records_loaded_from_case = records is None
        record_items = (
            pipeline.load_records(case.case_id)
            if records_loaded_from_case
            else tuple(records)
        )
        self._validate_case_items(
            case.case_id,
            (record.case_id for record in record_items),
            "record",
        )
        input_record_count = len(record_items)
        record_items = self._records_in_scope(record_items, plan)
        timeline_items = (
            TimelineBuilder().build(record_items)
            if timeline is None
            else tuple(timeline)
        )
        self._validate_case_items(
            case.case_id,
            (event.case_id for event in timeline_items),
            "timeline event",
        )

        findings = self._run_analyzers(record_items)
        alerts = self.rule_engine.evaluate(
            record_items,
            findings,
            rule_ids=self._profile_rule_ids(plan.options),
        )
        incidents = self.correlation_engine.correlate(
            alerts,
            findings=findings,
            timeline=timeline_items,
        )

        paths = self.repository.paths(case.case_id)
        previous_version = None
        if persist:
            previous_version = AnalysisHistoryService(
                self.repository.project,
                actor=self.actor,
            ).archive_current(case.case_id)

        result = AnalysisResult(
            case_id=case.case_id,
            record_count=len(record_items),
            finding_count=len(findings),
            alert_count=len(alerts),
            incident_count=len(incidents),
            findings=findings,
            alerts=alerts,
            incidents=incidents,
            findings_path=paths.findings_json if persist else None,
            alerts_path=paths.alerts_json if persist else None,
            incidents_path=paths.incidents_json if persist else None,
            previous_version_path=(
                previous_version.path
                if previous_version is not None
                else None
            ),
        )
        if persist:
            write_json(
                paths.findings_json,
                _envelope(case.case_id, "findings", findings),
            )
            write_json(
                paths.alerts_json,
                _envelope(case.case_id, "alerts", alerts),
            )
            write_json(
                paths.incidents_json,
                _envelope(case.case_id, "incidents", incidents),
            )
            AuditLogger(case.case_id, self.repository.project).log(
                "analysis_completed",
                actor=self.actor,
                details={
                    "input_record_count": input_record_count,
                    "record_count": result.record_count,
                    "finding_count": result.finding_count,
                    "alert_count": result.alert_count,
                    "incident_count": result.incident_count,
                    "previous_version_id": (
                        previous_version.version_id
                        if previous_version is not None
                        else None
                    ),
                },
            )
        return result

    @staticmethod
    def _profile_rule_ids(options: dict[str, Any]) -> tuple[str, ...] | None:
        values = options.get("detection_rules")
        if values is None:
            return None
        if not isinstance(values, list):
            raise AnalysisError(
                "collection_plan.options.detection_rules phải là list."
            )
        return tuple(str(value) for value in values)

    @staticmethod
    def _records_in_scope(
        records: tuple[NormalizedRecord, ...],
        plan,
    ) -> tuple[NormalizedRecord, ...]:
        if not records:
            return records
        if plan.time_range_start is not None:
            start = plan.time_range_start
            end = plan.time_range_end
        else:
            raw_hours = plan.options.get("default_time_window_hours", 24)
            if isinstance(raw_hours, bool):
                raise AnalysisError(
                    "default_time_window_hours phải là số nguyên dương."
                )
            try:
                hours = int(raw_hours)
            except (TypeError, ValueError) as exc:
                raise AnalysisError(
                    "default_time_window_hours phải là số nguyên dương."
                ) from exc
            if hours <= 0:
                raise AnalysisError(
                    "default_time_window_hours phải là số nguyên dương."
                )
            end = max(record.timestamp for record in records)
            start = end - timedelta(hours=hours)
        return tuple(
            record
            for record in records
            if start <= record.timestamp <= end
        )

    def load_findings(self, case_id: str) -> tuple[Finding, ...]:
        return self._load_models(
            case_id,
            "findings",
            self.repository.paths(case_id).findings_json,
            Finding.from_dict,
        )

    def load_alerts(self, case_id: str) -> tuple[Alert, ...]:
        return self._load_models(
            case_id,
            "alerts",
            self.repository.paths(case_id).alerts_json,
            Alert.from_dict,
        )

    def load_incidents(self, case_id: str) -> tuple[Incident, ...]:
        return self._load_models(
            case_id,
            "incidents",
            self.repository.paths(case_id).incidents_json,
            Incident.from_dict,
        )

    def set_incident_status(
        self,
        case_id: str,
        incident_id: str,
        status: IncidentStatus | str,
        *,
        conclusion: str,
        cia_impacts: tuple[CIAImpact | str, ...] = (),
    ) -> Incident:
        case = self.repository.require_open(case_id)
        normalized_status = (
            status
            if isinstance(status, IncidentStatus)
            else IncidentStatus(str(status))
        )
        conclusion_text = conclusion.strip()
        if not conclusion_text:
            raise AnalysisError(
                "Chuyên viên phải nhập kết luận khi đổi trạng thái."
            )
        if (
            normalized_status is IncidentStatus.CONFIRMED
            and not cia_impacts
        ):
            raise AnalysisError(
                "Incident Confirmed phải có ít nhất một tác động CIA."
            )
        incidents = list(self.load_incidents(case.case_id))
        for incident in incidents:
            if incident.incident_id != incident_id:
                continue
            incident.set_status(
                normalized_status,
                conclusion=conclusion_text,
                cia_impacts=cia_impacts,
                timestamp=max(utc_now(), incident.created_at),
            )
            write_json(
                self.repository.paths(case.case_id).incidents_json,
                _envelope(case.case_id, "incidents", incidents),
            )
            AuditLogger(case.case_id, self.repository.project).log(
                "incident_status_updated",
                actor=self.actor,
                details={
                    "incident_id": incident.incident_id,
                    "status": incident.status.value,
                    "cia_impacts": [
                        impact.value for impact in incident.cia_impacts
                    ],
                },
            )
            return incident
        raise AnalysisError(f"Không tìm thấy Incident: {incident_id}")

    def _run_analyzers(
        self,
        records: tuple[NormalizedRecord, ...],
    ) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for analyzer in self.analyzers:
            for finding in analyzer.analyze(records):
                if finding.finding_id in seen:
                    continue
                seen.add(finding.finding_id)
                findings.append(finding)
        return tuple(
            sorted(
                findings,
                key=lambda item: (
                    item.created_at,
                    item.finding_id,
                ),
            )
        )

    def _load_or_build_timeline(
        self,
        pipeline: ProcessingPipeline,
        case_id: str,
        records: tuple[NormalizedRecord, ...],
    ) -> tuple[TimelineEvent, ...]:
        try:
            return pipeline.load_timeline(case_id)
        except ProcessingError:
            return TimelineBuilder().build(records)

    def _load_models(
        self,
        case_id: str,
        key: str,
        path: Path,
        factory,
    ) -> tuple:
        case = self.repository.load_case(case_id)
        try:
            data = read_json_object(path)
        except JsonFileError as exc:
            raise AnalysisError(str(exc)) from exc
        _validate_envelope(data, case.case_id, key)
        try:
            return tuple(factory(item) for item in data[key])
        except (KeyError, TypeError, ValueError) as exc:
            raise AnalysisError(
                f"{key} chứa model không hợp lệ: {exc}"
            ) from exc

    @staticmethod
    def _validate_case_items(
        case_id: str,
        values: Iterable[str],
        label: str,
    ) -> None:
        if any(value != case_id for value in values):
            raise AnalysisError(
                f"Analysis chứa {label} khác Case."
            )


def _envelope(
    case_id: str,
    key: str,
    values: Iterable,
) -> dict[str, Any]:
    items = tuple(values)
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        f"{key[:-1]}_count": len(items),
        key: [item.to_dict() for item in items],
    }


def _validate_envelope(
    data: dict[str, Any],
    case_id: str,
    key: str,
) -> None:
    if data.get("schema_version") != SCHEMA_VERSION:
        raise AnalysisError("Analysis schema_version không hỗ trợ.")
    if data.get("case_id") != case_id:
        raise AnalysisError(f"{key} không khớp Case.")
    items = data.get(key)
    count = data.get(f"{key[:-1]}_count")
    if (
        not isinstance(items, list)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != len(items)
        or any(not isinstance(item, dict) for item in items)
    ):
        raise AnalysisError(f"{key} envelope không hợp lệ.")
