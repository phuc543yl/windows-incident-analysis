"""Report format selection and generated-output display tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from ui.components.data_table import Column, DataTable


class ReportTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_generate: Callable[[tuple[str, ...]], None],
    ) -> None:
        super().__init__(parent, padding=12)
        self.on_generate = on_generate
        controls = ttk.LabelFrame(self, text="Định dạng báo cáo", padding=10)
        controls.pack(fill=tk.X, pady=(0, 10))
        self.format_vars = {
            name: tk.BooleanVar(value=name in {"html", "json"})
            for name in ("html", "pdf", "json", "csv")
        }
        for name, variable in self.format_vars.items():
            ttk.Checkbutton(
                controls,
                text=name.upper(),
                variable=variable,
            ).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(
            controls,
            text="Xuất báo cáo",
            command=self._generate,
        ).pack(side=tk.RIGHT)
        self.table = DataTable(
            self,
            (
                Column("format", "Định dạng", 110),
                Column("path", "Đường dẫn", 700),
            ),
            height=12,
        )
        self.table.pack(fill=tk.BOTH, expand=True)

    def set_result(self, result: dict[str, Any]) -> None:
        rows = [
            {"format": report_format.upper(), "path": path}
            for report_format, path in result.get(
                "output_paths", {}
            ).items()
        ]
        self.table.set_rows(rows, id_key="format")

    def _generate(self) -> None:
        formats = tuple(
            name
            for name, variable in self.format_vars.items()
            if variable.get()
        )
        self.on_generate(formats)
