"""JSON investigation report exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from common.exceptions import JsonFileError, ReportError
from common.json_utils import write_json


class JsonExporter:
    def export(
        self,
        report: dict[str, Any],
        output_path: str | Path,
    ) -> Path:
        try:
            return write_json(output_path, report)
        except JsonFileError as exc:
            raise ReportError(str(exc)) from exc
