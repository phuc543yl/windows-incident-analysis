"""UTF-8 CSV exporter for the investigation timeline."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from common.exceptions import ReportError


class CsvExporter:
    FIELDNAMES = (
        "timeline_event_id",
        "timestamp",
        "event_type",
        "hostname",
        "user",
        "summary",
        "source_record_ids",
        "finding_ids",
        "alert_ids",
        "evidence_item_ids",
        "details_json",
    )

    def export(
        self,
        timeline: Iterable[dict[str, Any]],
        output_path: str | Path,
    ) -> Path:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8-sig",
                newline="",
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=self.FIELDNAMES,
                    lineterminator="\n",
                )
                writer.writeheader()
                for event in timeline:
                    if not isinstance(event, dict):
                        raise ReportError(
                            "Timeline CSV chỉ chấp nhận các object."
                        )
                    writer.writerow(self._row(event))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, destination)
        except Exception as exc:
            temporary_path.unlink(missing_ok=True)
            if isinstance(exc, ReportError):
                raise
            raise ReportError(f"Không thể xuất CSV {destination}: {exc}") from exc
        return destination

    @staticmethod
    def _row(event: dict[str, Any]) -> dict[str, str]:
        def joined(key: str) -> str:
            value = event.get(key, [])
            if isinstance(value, (list, tuple)):
                return ";".join(str(item) for item in value)
            return str(value or "")

        details = event.get("details", {})
        return {
            "timeline_event_id": str(
                event.get("timeline_event_id", "")
            ),
            "timestamp": str(event.get("timestamp", "")),
            "event_type": str(event.get("event_type", "")),
            "hostname": str(event.get("hostname", "")),
            "user": str(event.get("user", "")),
            "summary": str(event.get("summary", "")),
            "source_record_ids": joined("source_record_ids"),
            "finding_ids": joined("finding_ids"),
            "alert_ids": joined("alert_ids"),
            "evidence_item_ids": joined("evidence_item_ids"),
            "details_json": json.dumps(
                details,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
