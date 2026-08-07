"""PDF investigation report exporter implemented with ReportLab."""

from __future__ import annotations

import html
import os
import tempfile
from pathlib import Path
from typing import Any

from common.exceptions import ReportError


class PdfExporter:
    def export(
        self,
        report: dict[str, Any],
        output_path: str | Path,
    ) -> Path:
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            from reportlab.platypus import (
                PageBreak,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise ReportError(
                "Xuất PDF cần thư viện reportlab."
            ) from exc

        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".pdf",
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        font_name = _register_unicode_font(pdfmetrics, TTFont)

        try:
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "ReportTitle",
                parent=styles["Title"],
                fontName=font_name,
                fontSize=18,
                leading=23,
                alignment=TA_CENTER,
                textColor=colors.HexColor("#17324D"),
                spaceAfter=10,
            )
            heading_style = ParagraphStyle(
                "ReportHeading",
                parent=styles["Heading2"],
                fontName=font_name,
                fontSize=13,
                leading=17,
                textColor=colors.HexColor("#17324D"),
                spaceBefore=8,
                spaceAfter=6,
            )
            body_style = ParagraphStyle(
                "ReportBody",
                parent=styles["BodyText"],
                fontName=font_name,
                fontSize=8.5,
                leading=11,
            )
            document = SimpleDocTemplate(
                str(temporary_path),
                pagesize=A4,
                rightMargin=15 * mm,
                leftMargin=15 * mm,
                topMargin=15 * mm,
                bottomMargin=15 * mm,
                title=f"Báo cáo điều tra {report.get('case', {}).get('case_id', '')}",
                author=str(report.get("generator", {}).get("name", "")),
            )
            story: list[Any] = []
            case = _mapping(report.get("case"))
            target = _mapping(report.get("target"))
            summary = _mapping(report.get("summary"))
            story.append(
                Paragraph(
                    "BÁO CÁO ĐIỀU TRA SỰ CỐ WINDOWS",
                    title_style,
                )
            )
            story.append(
                Paragraph(
                    _paragraph(
                        f"{case.get('case_id', '')} — "
                        f"{case.get('title', '')}"
                    ),
                    body_style,
                )
            )
            story.append(Spacer(1, 6))
            story.extend(
                _section_table(
                    "Thông tin vụ việc",
                    (
                        ("Mã vụ việc", case.get("case_id", "")),
                        ("Trạng thái", case.get("status", "")),
                        ("Chuyên viên", case.get("created_by", "")),
                        ("Hostname", target.get("hostname", "")),
                        ("Hệ điều hành", target.get("os_name", "")),
                        ("Giả thuyết", case.get("hypothesis", "")),
                    ),
                    heading_style,
                    body_style,
                    Table,
                    TableStyle,
                    colors,
                )
            )
            story.extend(
                _section_table(
                    "Tổng quan kết quả",
                    tuple(
                        (key.replace("_", " ").title(), value)
                        for key, value in summary.items()
                    ),
                    heading_style,
                    body_style,
                    Table,
                    TableStyle,
                    colors,
                )
            )

            evidence = _mapping(report.get("evidence"))
            execution = _mapping(report.get("execution"))
            analysis = _mapping(report.get("analysis"))
            analyst = _mapping(report.get("analyst"))
            _append_records(
                story,
                "Bằng chứng",
                evidence.get("items", []),
                ("evidence_id", "artifact_type", "stored_path", "sha256"),
                heading_style,
                body_style,
                Paragraph,
            )
            _append_records(
                story,
                "Lần chạy công cụ",
                execution.get("tool_runs", []),
                ("tool_id", "status", "started_at", "exit_code"),
                heading_style,
                body_style,
                Paragraph,
            )
            _append_records(
                story,
                "Finding",
                analysis.get("findings", []),
                ("finding_id", "title", "severity", "description"),
                heading_style,
                body_style,
                Paragraph,
            )
            _append_records(
                story,
                "Alert",
                analysis.get("alerts", []),
                ("alert_id", "title", "severity", "risk_score"),
                heading_style,
                body_style,
                Paragraph,
            )
            _append_records(
                story,
                "Incident",
                analysis.get("incidents", []),
                (
                    "incident_id",
                    "title",
                    "status",
                    "cia_impacts",
                    "analyst_conclusion",
                ),
                heading_style,
                body_style,
                Paragraph,
            )
            story.append(PageBreak())
            _append_records(
                story,
                "Timeline",
                analysis.get("timeline", []),
                ("timestamp", "event_type", "hostname", "user", "summary"),
                heading_style,
                body_style,
                Paragraph,
            )
            story.append(Paragraph("Kết luận chuyên viên", heading_style))
            conclusion = _mapping(analyst.get("conclusion"))
            story.append(
                Paragraph(
                    _paragraph(
                        conclusion.get(
                            "conclusion",
                            conclusion.get(
                                "analyst_conclusion",
                                "Chưa có kết luận.",
                            ),
                        )
                    ),
                    body_style,
                )
            )
            story.append(Paragraph("Khuyến nghị", heading_style))
            recommendations = analyst.get("recommendations", [])
            if recommendations:
                for value in recommendations:
                    story.append(
                        Paragraph(f"• {_paragraph(value)}", body_style)
                    )
            else:
                story.append(Paragraph("Chưa có khuyến nghị.", body_style))
            document.build(story)
            os.replace(temporary_path, destination)
        except Exception as exc:
            temporary_path.unlink(missing_ok=True)
            if isinstance(exc, ReportError):
                raise
            raise ReportError(f"Không thể xuất PDF {destination}: {exc}") from exc
        return destination


def _register_unicode_font(pdfmetrics: Any, ttf_class: Any) -> str:
    font_name = "CrowEyeUnicode"
    if font_name in pdfmetrics.getRegisteredFontNames():
        return font_name
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    candidates = (
        windows / "Fonts" / "arial.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
        Path("/Library/Fonts/Arial Unicode.ttf"),
    )
    for path in candidates:
        if path.is_file():
            pdfmetrics.registerFont(ttf_class(font_name, str(path)))
            return font_name
    return "Helvetica"


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _paragraph(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value)
    return html.escape(str(value), quote=True).replace("\n", "<br/>")


def _section_table(
    title: str,
    rows: tuple[tuple[str, Any], ...],
    heading_style: Any,
    body_style: Any,
    table_class: Any,
    table_style_class: Any,
    colors: Any,
) -> list[Any]:
    from reportlab.platypus import Paragraph

    data = [
        [
            Paragraph(_paragraph(label), body_style),
            Paragraph(_paragraph(value), body_style),
        ]
        for label, value in rows
    ]
    table = table_class(data, colWidths=[42 * 2.83465, 128 * 2.83465])
    table.setStyle(
        table_style_class(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0F6")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C5D1DC")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return [Paragraph(_paragraph(title), heading_style), table]


def _append_records(
    story: list[Any],
    title: str,
    records: Any,
    fields: tuple[str, ...],
    heading_style: Any,
    body_style: Any,
    paragraph_class: Any,
) -> None:
    story.append(paragraph_class(_paragraph(title), heading_style))
    if not isinstance(records, list) or not records:
        story.append(paragraph_class("Chưa có dữ liệu.", body_style))
        return
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue
        values = " | ".join(
            f"{field}: {_paragraph(record.get(field, ''))}"
            for field in fields
        )
        story.append(
            paragraph_class(f"{index}. {values}", body_style)
        )
        story.append(paragraph_class(" ", body_style))
