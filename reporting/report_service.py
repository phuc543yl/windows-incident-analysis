"""Generate all requested report formats for one Case."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.constants import SUPPORTED_REPORT_FORMATS
from common.exceptions import ReportError
from reporting.exporters import (
    CsvExporter,
    HtmlExporter,
    JsonExporter,
    PdfExporter,
)
from reporting.report_builder import ReportBuilder
from reporting.report_context import ReportContextBuilder


@dataclass(frozen=True, slots=True)
class ReportResult:
    case_id: str
    formats: tuple[str, ...]
    output_paths: dict[str, Path]

    def path_for(self, report_format: str) -> Path:
        normalized = str(report_format).strip().lower()
        try:
            return self.output_paths[normalized]
        except KeyError as exc:
            raise ReportError(
                f"Định dạng chưa được tạo: {report_format}"
            ) from exc


class ReportService:
    FILE_NAMES = {
        "html": "investigation_report.html",
        "pdf": "investigation_report.pdf",
        "json": "investigation_report.json",
        "csv": "timeline.csv",
    }

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.context_builder = ReportContextBuilder(
            self.repository.project
        )
        self.report_builder = ReportBuilder()
        self.actor = actor.strip() or "analyst"
        self.exporters = {
            "html": HtmlExporter(),
            "pdf": PdfExporter(),
            "json": JsonExporter(),
            "csv": CsvExporter(),
        }

    def generate(
        self,
        case_id: str,
        formats: Iterable[str] = SUPPORTED_REPORT_FORMATS,
    ) -> ReportResult:
        normalized_formats = _normalize_formats(formats)
        context = self.context_builder.build(case_id)
        report = self.report_builder.build(context)
        reports_directory = self.repository.paths(case_id).reports
        reports_directory.mkdir(parents=True, exist_ok=True)

        output_paths: dict[str, Path] = {}
        for report_format in normalized_formats:
            destination = (
                reports_directory / self.FILE_NAMES[report_format]
            )
            if report_format == "csv":
                timeline = report["analysis"]["timeline"]
                output_paths[report_format] = self.exporters[
                    report_format
                ].export(timeline, destination)
            else:
                output_paths[report_format] = self.exporters[
                    report_format
                ].export(report, destination)

        AuditLogger(case_id, self.repository.project).log(
            "report_generated",
            actor=self.actor,
            details={
                "formats": list(normalized_formats),
                "output_files": [
                    path.relative_to(
                        self.repository.paths(case_id).root
                    ).as_posix()
                    for path in output_paths.values()
                ],
            },
        )
        return ReportResult(
            case_id=context.case_id,
            formats=normalized_formats,
            output_paths=output_paths,
        )


def _normalize_formats(formats: Iterable[str]) -> tuple[str, ...]:
    if isinstance(formats, str):
        values = (formats,)
    else:
        try:
            values = tuple(formats)
        except TypeError as exc:
            raise TypeError("formats phải là iterable.") from exc
    normalized: list[str] = []
    for value in values:
        report_format = str(value).strip().lower()
        if report_format not in SUPPORTED_REPORT_FORMATS:
            raise ReportError(
                f"Định dạng báo cáo không được hỗ trợ: {value}"
            )
        if report_format not in normalized:
            normalized.append(report_format)
    if not normalized:
        raise ReportError("Phải chọn ít nhất một định dạng báo cáo.")
    return tuple(normalized)
