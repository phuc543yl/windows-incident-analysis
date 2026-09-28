"""Self-contained HTML investigation report exporter."""

from __future__ import annotations

import html
import os
import tempfile
from pathlib import Path
from string import Template
from typing import Any, Iterable

from common.exceptions import ReportError


class HtmlExporter:
    def __init__(
        self,
        template_directory: str | Path | None = None,
    ) -> None:
        self.template_directory = (
            Path(template_directory)
            if template_directory is not None
            else Path(__file__).resolve().parents[1] / "templates"
        )

    def export(
        self,
        report: dict[str, Any],
        output_path: str | Path,
    ) -> Path:
        template_path = (
            self.template_directory / "investigation_report.html"
        )
        style_path = self.template_directory / "report_style.css"
        try:
            template = Template(
                template_path.read_text(encoding="utf-8")
            )
            styles = style_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"Không thể đọc template báo cáo: {exc}") from exc

        case = _mapping(report.get("case"))
        target = _mapping(report.get("target"))
        scope = _mapping(report.get("scope"))
        evidence = _mapping(report.get("evidence"))
        execution = _mapping(report.get("execution"))
        analysis = _mapping(report.get("analysis"))
        analyst = _mapping(report.get("analyst"))
        summary = _mapping(report.get("summary"))

        substitutions = {
            "styles": styles,
            "report_title": _escape(
                f"Báo cáo điều tra sự cố - {case.get('case_id', '')}"
            ),
            "case_title": _escape(case.get("title", "")),
            "generated_at": _escape(report.get("generated_at", "")),
            "case_summary": _key_value_table(
                (
                    ("Mã vụ việc", case.get("case_id")),
                    ("Trạng thái", case.get("status")),
                    ("Chuyên viên", case.get("created_by")),
                    ("Ngày tạo", case.get("created_at")),
                    ("Mô tả", case.get("description")),
                )
            ),
            "target_summary": _key_value_table(
                (
                    ("Hostname", target.get("hostname")),
                    ("Địa chỉ IP", target.get("ip_addresses")),
                    ("Hệ điều hành", target.get("os_name")),
                    ("Phiên bản", target.get("os_version")),
                    ("Kiến trúc", target.get("architecture")),
                    ("Domain", target.get("domain")),
                )
            ),
            "scope_summary": _key_value_table(
                (
                    ("Profile", scope.get("profile_id")),
                    ("Chế độ", scope.get("mode")),
                    ("Giả thuyết", scope.get("hypothesis")),
                    ("Bắt đầu", scope.get("time_range_start")),
                    ("Kết thúc", scope.get("time_range_end")),
                    ("Live collectors", scope.get("live_collectors")),
                    (
                        "Artifact collectors",
                        scope.get("artifact_collectors"),
                    ),
                )
            ),
            "counts": _key_value_table(
                (
                    ("Bằng chứng", summary.get("evidence_count", 0)),
                    ("Lần thu thập", summary.get("collection_run_count", 0)),
                    ("Lần chạy công cụ", summary.get("tool_run_count", 0)),
                    ("Finding", summary.get("finding_count", 0)),
                    ("Alert", summary.get("alert_count", 0)),
                    ("Incident", summary.get("incident_count", 0)),
                    ("Sự kiện timeline", summary.get("timeline_event_count", 0)),
                )
            ),
            "evidence_table": _object_table(
                evidence.get("items", []),
                (
                    ("evidence_id", "Evidence ID"),
                    ("artifact_type", "Artifact"),
                    ("stored_path", "Đường dẫn lưu"),
                    ("sha256", "SHA-256"),
                    ("size_bytes", "Kích thước"),
                ),
            ),
            "collection_table": _object_table(
                execution.get("collection_runs", []),
                (
                    ("collector_id", "Collector"),
                    ("status", "Trạng thái"),
                    ("started_at", "Bắt đầu"),
                    ("finished_at", "Kết thúc"),
                    ("record_count", "Số bản ghi"),
                ),
            ),
            "tool_table": _object_table(
                execution.get("tool_runs", []),
                (
                    ("tool_id", "Công cụ"),
                    ("status", "Trạng thái"),
                    ("started_at", "Bắt đầu"),
                    ("exit_code", "Exit code"),
                    ("output_files", "Đầu ra"),
                ),
            ),
            "findings": _cards(
                analysis.get("findings", []),
                "finding_id",
                "title",
                ("severity", "description", "mitre_techniques"),
            ),
            "alerts": _cards(
                analysis.get("alerts", []),
                "alert_id",
                "title",
                ("severity", "risk_score", "description", "recommendation"),
            ),
            "incidents": _cards(
                analysis.get("incidents", []),
                "incident_id",
                "title",
                (
                    "status",
                    "confidence_score",
                    "cia_impacts",
                    "analyst_conclusion",
                    "recommendations",
                ),
            ),
            "cia_evidence": _cards(
                [
                    item
                    for item in analysis.get("incidents", [])
                    if item.get("cia_impacts")
                ],
                "incident_id",
                "title",
                (
                    "cia_impacts",
                    "status",
                    "analyst_conclusion",
                ),
            ),
            "story_table": _object_table(
                analysis.get("story")
                or analysis.get("timeline", [])[:8],
                (
                    ("timestamp", "Thời điểm"),
                    ("title", "Mốc"),
                    ("summary", "Tóm tắt"),
                    ("incident_id", "Incident"),
                )
                if analysis.get("story")
                else (
                    ("timestamp", "Thời điểm"),
                    ("event_type", "Loại"),
                    ("summary", "Tóm tắt"),
                    ("hostname", "Hostname"),
                ),
            ),
            "timeline_table": _object_table(
                analysis.get("timeline", []),
                (
                    ("timestamp", "Timestamp"),
                    ("event_type", "Loại"),
                    ("hostname", "Hostname"),
                    ("user", "User"),
                    ("summary", "Tóm tắt"),
                ),
            ),
            "analyst_section": _analyst_section(analyst),
        }
        document = template.safe_substitute(substitutions)
        return _atomic_write(output_path, document)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _escape(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value)
    return html.escape(str(value), quote=True)


def _key_value_table(rows: Iterable[tuple[str, Any]]) -> str:
    body = "".join(
        "<tr>"
        f"<th scope=\"row\">{_escape(label)}</th>"
        f"<td>{_escape(value)}</td>"
        "</tr>"
        for label, value in rows
    )
    return f'<table class="key-value"><tbody>{body}</tbody></table>'


def _object_table(
    items: Any,
    columns: tuple[tuple[str, str], ...],
) -> str:
    if not isinstance(items, list) or not items:
        return '<p class="empty">Chưa có dữ liệu.</p>'
    header = "".join(
        f"<th scope=\"col\">{_escape(label)}</th>"
        for _, label in columns
    )
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cells = "".join(
            f"<td>{_escape(item.get(key, ''))}</td>"
            for key, _ in columns
        )
        rows.append(f"<tr>{cells}</tr>")
    return (
        '<div class="table-scroll"><table><thead><tr>'
        f"{header}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _cards(
    items: Any,
    id_key: str,
    title_key: str,
    fields: tuple[str, ...],
) -> str:
    if not isinstance(items, list) or not items:
        return '<p class="empty">Chưa có dữ liệu.</p>'
    cards: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        details = "".join(
            f"<dt>{_escape(field.replace('_', ' ').title())}</dt>"
            f"<dd>{_escape(item.get(field, ''))}</dd>"
            for field in fields
            if item.get(field) not in (None, "", [], ())
        )
        cards.append(
            '<article class="card">'
            f"<h3>{_escape(item.get(title_key, ''))}</h3>"
            f"<p class=\"identifier\">{_escape(item.get(id_key, ''))}</p>"
            f"<dl>{details}</dl>"
            "</article>"
        )
    return "".join(cards) or '<p class="empty">Chưa có dữ liệu.</p>'


def _analyst_section(analyst: dict[str, Any]) -> str:
    conclusion = _mapping(analyst.get("conclusion"))
    notes = analyst.get("notes", [])
    recommendations = analyst.get("recommendations", [])
    note_items = "".join(
        f"<li>{_escape(note.get('text', note.get('note', note)))}</li>"
        for note in notes
        if isinstance(note, dict)
    )
    recommendation_items = "".join(
        f"<li>{_escape(value)}</li>" for value in recommendations
    )
    conclusion_text = conclusion.get(
        "conclusion",
        conclusion.get("analyst_conclusion", ""),
    )
    return (
        "<h3>Kết luận</h3>"
        f"<p>{_escape(conclusion_text) or 'Chưa có kết luận.'}</p>"
        "<h3>Ghi chú</h3>"
        f"<ul>{note_items or '<li>Chưa có ghi chú.</li>'}</ul>"
        "<h3>Khuyến nghị</h3>"
        f"<ul>{recommendation_items or '<li>Chưa có khuyến nghị.</li>'}</ul>"
    )


def _atomic_write(output_path: str | Path, content: str) -> Path:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
    except OSError as exc:
        temporary_path.unlink(missing_ok=True)
        raise ReportError(
            f"Không thể xuất HTML {destination}: {exc}"
        ) from exc
    return destination
