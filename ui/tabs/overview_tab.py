"""Case overview, health, and next-step guidance."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any


class OverviewTab(ttk.Frame):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, padding=10)
        self.summary_var = tk.StringVar(value="Chưa chọn Case.")
        ttk.Label(self, textvariable=self.summary_var, wraplength=1100).pack(
            anchor=tk.W,
            pady=(0, 8),
        )
        columns = ttk.Frame(self)
        columns.pack(fill=tk.BOTH, expand=True)
        self.counts = _kv_box(columns, "Tổng quan Case")
        self.counts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.tools = _kv_box(columns, "DFIR tools")
        self.tools.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.next_steps = _kv_box(columns, "Bước tiếp theo")
        self.next_steps.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def set_overview(self, data: dict[str, Any]) -> None:
        case = data.get("case") or {}
        self.summary_var.set(
            f"{case.get('case_id', 'Chưa chọn Case')} — "
            f"{case.get('title', '')} | profile={case.get('profile_id', '')} | "
            f"status={case.get('status', '')}"
        )
        _set_lines(
            self.counts,
            (
                f"Evidence: {data.get('evidence_count', 0)}",
                f"Hash verify: {data.get('integrity', 'chưa kiểm tra')}",
                f"Findings: {data.get('finding_count', 0)}",
                f"Alerts: {data.get('alert_count', 0)}",
                f"Incidents: {data.get('incident_count', 0)}",
                f"CIA đã chọn: {data.get('cia', 'chưa có')}",
                f"Giả thuyết: {data.get('hypothesis', '')}",
            ),
        )
        _set_lines(self.tools, data.get("tool_lines") or ("Chưa kiểm tra tool.",))
        _set_lines(self.next_steps, data.get("next_steps") or ("Mở Case và thu thập.",))


def _kv_box(parent: tk.Misc, title: str) -> ttk.LabelFrame:
    frame = ttk.LabelFrame(parent, text=title, padding=8)
    frame._text = tk.Text(frame, height=14, wrap=tk.WORD, relief=tk.FLAT)
    frame._text.pack(fill=tk.BOTH, expand=True)
    frame._text.configure(state=tk.DISABLED)
    return frame


def _set_lines(frame: ttk.LabelFrame, lines: tuple[str, ...] | list[str]) -> None:
    widget: tk.Text = frame._text
    widget.configure(state=tk.NORMAL)
    widget.delete("1.0", tk.END)
    widget.insert("1.0", "\n".join(lines))
    widget.configure(state=tk.DISABLED)
