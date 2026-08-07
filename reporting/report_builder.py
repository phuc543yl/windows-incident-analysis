"""Build a format-neutral investigation report document."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from common.constants import APP_NAME, APP_VERSION
from common.time_utils import to_iso8601, utc_now
from reporting.report_context import ReportContext


class ReportBuilder:
    """Convert one context snapshot into a stable, serializable schema."""

    SCHEMA_VERSION = 1

    def build(
        self,
        context: ReportContext,
        *,
        generated_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_now() if generated_at is None else generated_at
        generated_text = (
            timestamp
            if isinstance(timestamp, str)
            else to_iso8601(timestamp)
        )
        plan = context.collection_plan
        manifest = context.manifest
        evidence_items = manifest.get("evidence_items", [])

        return {
            "schema_version": self.SCHEMA_VERSION,
            "report_type": "windows_incident_investigation",
            "generated_at": generated_text,
            "generator": {
                "name": APP_NAME,
                "version": APP_VERSION,
            },
            "case": dict(context.case),
            "target": dict(context.target),
            "scope": {
                "profile_id": context.case.get("profile_id", ""),
                "mode": context.case.get("mode", ""),
                "hypothesis": context.case.get("hypothesis", ""),
                "time_range_start": plan.get("time_range_start"),
                "time_range_end": plan.get("time_range_end"),
                "live_collectors": list(plan.get("live_collectors", [])),
                "artifact_collectors": list(
                    plan.get("artifact_collectors", [])
                ),
            },
            "evidence": {
                "manifest": {
                    key: value
                    for key, value in manifest.items()
                    if key != "evidence_items"
                },
                "items": [dict(item) for item in evidence_items],
                "chain_of_custody": dict(context.chain_of_custody),
            },
            "execution": {
                "collection_runs": [
                    dict(item) for item in context.collection_runs
                ],
                "tool_runs": [
                    _safe_tool_run(item) for item in context.tool_runs
                ],
            },
            "analysis": {
                "findings": [dict(item) for item in context.findings],
                "alerts": [dict(item) for item in context.alerts],
                "incidents": [dict(item) for item in context.incidents],
                "timeline": [dict(item) for item in context.timeline],
            },
            "analyst": {
                "notes": [dict(item) for item in context.analyst_notes],
                "conclusion": dict(context.analyst_conclusion),
                "recommendations": list(context.recommendations),
            },
            "summary": {
                "evidence_count": len(evidence_items),
                "evidence_size_bytes": int(
                    manifest.get("total_size_bytes", 0) or 0
                ),
                "collection_run_count": len(context.collection_runs),
                "tool_run_count": len(context.tool_runs),
                "finding_count": len(context.findings),
                "alert_count": len(context.alerts),
                "incident_count": len(context.incidents),
                "timeline_event_count": len(context.timeline),
            },
        }


def _safe_tool_run(item: dict[str, Any]) -> dict[str, Any]:
    """Keep report-relevant execution metadata without leaking arguments."""
    allowed = {
        "case_id",
        "tool_id",
        "tool_result_id",
        "status",
        "started_at",
        "finished_at",
        "duration_seconds",
        "exit_code",
        "output_files",
        "stdout_path",
        "stderr_path",
        "error_message",
        "metadata",
    }
    return {
        key: value
        for key, value in item.items()
        if key in allowed
    }
