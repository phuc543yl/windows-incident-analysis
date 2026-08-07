"""Collection Plan display and execution results tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Iterable

from ui.components.data_table import Column, DataTable


class CollectionTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_collect: Callable[[str, str | None], None],
    ) -> None:
        super().__init__(parent, padding=10)
        self.on_collect = on_collect
        self.mode_var = tk.StringVar(value="local")
        self.agent_id_var = tk.StringVar()
        self.plan_var = tk.StringVar(value="Chưa chọn Case.")

        controls = ttk.LabelFrame(self, text="Collection Plan", padding=10)
        controls.pack(fill=tk.X)
        ttk.Label(
            controls,
            textvariable=self.plan_var,
            wraplength=900,
        ).grid(row=0, column=0, columnspan=6, sticky="w", pady=(0, 8))
        ttk.Label(controls, text="Mode").grid(row=1, column=0, sticky="w")
        ttk.Combobox(
            controls,
            textvariable=self.mode_var,
            values=("local", "agent"),
            state="readonly",
            width=12,
        ).grid(row=1, column=1, padx=(6, 18))
        ttk.Label(controls, text="Agent ID").grid(row=1, column=2, sticky="w")
        ttk.Entry(
            controls,
            textvariable=self.agent_id_var,
            width=24,
        ).grid(row=1, column=3, padx=(6, 18))
        ttk.Button(
            controls,
            text="Bắt đầu thu thập",
            command=self._collect,
        ).grid(row=1, column=4)

        frame = ttk.LabelFrame(self, text="Kết quả collector", padding=8)
        frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.table = DataTable(
            frame,
            (
                Column("collector_id", "Collector", 150),
                Column("status", "Trạng thái", 100),
                Column("record_count", "Bản ghi", 80),
                Column("duration_seconds", "Thời gian (s)", 100),
                Column("warnings", "Cảnh báo", 240),
                Column("errors", "Lỗi", 240),
            ),
            height=16,
        )
        self.table.pack(fill=tk.BOTH, expand=True)

    def set_context(self, context: dict[str, Any]) -> None:
        plan = context["collection_plan"]
        target = context["target"]
        self.mode_var.set(plan.get("mode", "local"))
        self.agent_id_var.set(
            plan.get("target_agent_id") or target.get("agent_id") or ""
        )
        collectors = (
            *plan.get("live_collectors", []),
            *plan.get("artifact_collectors", []),
        )
        self.plan_var.set(
            f"Profile: {plan.get('profile_id', '')} | "
            f"Collectors: {', '.join(collectors) or 'không có'}"
        )

    def set_results(self, results: Iterable[dict[str, Any]]) -> None:
        self.table.set_rows(results, id_key="result_id")

    def _collect(self) -> None:
        self.on_collect(
            self.mode_var.get(),
            self.agent_id_var.get().strip() or None,
        )
