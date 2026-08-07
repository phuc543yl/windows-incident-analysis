"""Findings, alerts, incidents, and analyst confirmation tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable

from ui.components.data_table import Column, DataTable


class AnalysisTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_process: Callable[[], None],
        on_analyze: Callable[[], None],
        on_refresh: Callable[[], None],
        on_set_incident: Callable[
            [str, str, str, tuple[str, ...]], None
        ],
    ) -> None:
        super().__init__(parent, padding=10)
        self.on_set_incident = on_set_incident
        actions = ttk.Frame(self)
        actions.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(
            actions,
            text="1. Xử lý dữ liệu thô",
            command=on_process,
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            actions, text="2. Chạy phân tích", command=on_analyze
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            actions, text="Làm mới kết quả", command=on_refresh
        ).pack(side=tk.LEFT)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)
        self.findings = DataTable(
            notebook,
            (
                Column("finding_id", "Finding ID", 175),
                Column("severity", "Mức độ", 90),
                Column("title", "Tiêu đề", 240),
                Column("description", "Mô tả", 360),
                Column("mitre_techniques", "MITRE", 130),
            ),
        )
        self.alerts = DataTable(
            notebook,
            (
                Column("alert_id", "Alert ID", 175),
                Column("severity", "Mức độ", 90),
                Column("risk_score", "Risk", 70),
                Column("title", "Tiêu đề", 220),
                Column("recommendation", "Khuyến nghị", 360),
            ),
        )
        incident_frame = ttk.Frame(notebook)
        self.incidents = DataTable(
            incident_frame,
            (
                Column("incident_id", "Incident ID", 175),
                Column("status", "Trạng thái", 120),
                Column("confidence_score", "Tin cậy", 80),
                Column("title", "Tiêu đề", 220),
                Column("cia_impacts", "CIA", 160),
                Column("analyst_conclusion", "Kết luận", 300),
            ),
            height=9,
        )
        self.incidents.pack(fill=tk.BOTH, expand=True)
        decision = ttk.LabelFrame(
            incident_frame,
            text="Xác nhận của chuyên viên",
            padding=8,
        )
        decision.pack(fill=tk.X, pady=(8, 0))
        self.status_var = tk.StringVar(value="confirmed")
        ttk.Combobox(
            decision,
            textvariable=self.status_var,
            values=(
                "confirmed",
                "not_confirmed",
                "false_positive",
                "closed",
            ),
            state="readonly",
            width=18,
        ).grid(row=0, column=0, padx=(0, 8))
        self.cia_vars = {
            name: tk.BooleanVar()
            for name in ("confidentiality", "integrity", "availability")
        }
        for column, (name, variable) in enumerate(
            self.cia_vars.items(), start=1
        ):
            ttk.Checkbutton(
                decision,
                text=name.title(),
                variable=variable,
            ).grid(row=0, column=column, padx=4)
        self.conclusion_var = tk.StringVar()
        ttk.Entry(
            decision,
            textvariable=self.conclusion_var,
        ).grid(row=1, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        ttk.Button(
            decision,
            text="Lưu quyết định",
            command=self._save_decision,
        ).grid(row=1, column=4, padx=(8, 0), pady=(8, 0))
        decision.columnconfigure(3, weight=1)

        notebook.add(self.findings, text="Findings")
        notebook.add(self.alerts, text="Alerts")
        notebook.add(incident_frame, text="Incidents")

    def set_results(self, results: dict[str, Any]) -> None:
        self.findings.set_rows(
            results.get("findings", []),
            id_key="finding_id",
        )
        self.alerts.set_rows(
            results.get("alerts", []),
            id_key="alert_id",
        )
        self.incidents.set_rows(
            results.get("incidents", []),
            id_key="incident_id",
        )

    def _save_decision(self) -> None:
        incident = self.incidents.selected_record()
        if incident is None:
            messagebox.showinfo("Crow-Eye", "Hãy chọn một Incident.")
            return
        impacts = tuple(
            name for name, variable in self.cia_vars.items() if variable.get()
        )
        self.on_set_incident(
            incident["incident_id"],
            self.status_var.get(),
            self.conclusion_var.get().strip(),
            impacts,
        )
