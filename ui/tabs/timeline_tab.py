"""Chronological normalized incident timeline tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Iterable

from ui.components.data_table import Column, DataTable
from ui.timeline_filter import TimelineFilter, filter_timeline_events


class TimelineTab(ttk.Frame):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, padding=10)
        self._events: tuple[dict[str, Any], ...] = ()
        self._build_filters()
        self.table = DataTable(
            self,
            (
                Column("timestamp", "Timestamp (UTC)", 185),
                Column("event_type", "Loại sự kiện", 145),
                Column("event_id", "Event ID", 80),
                Column("hostname", "Hostname", 130),
                Column("user", "User", 125),
                Column("ip", "IP", 150),
                Column("summary", "Tóm tắt", 360),
                Column("finding_ids", "Finding", 165),
                Column("alert_ids", "Alert", 165),
            ),
            height=20,
        )
        self.table.pack(fill=tk.BOTH, expand=True)

    def set_events(self, events: Iterable[dict[str, Any]]) -> None:
        self._events = tuple(dict(event) for event in events)
        self.apply_filters(show_errors=False)

    def apply_filters(self, *, show_errors: bool = True) -> None:
        try:
            criteria = TimelineFilter.from_text(
                start=self.start_var.get(),
                end=self.end_var.get(),
                event_id=self.event_id_var.get(),
                hostname=self.hostname_var.get(),
                user=self.user_var.get(),
                ip=self.ip_var.get(),
            )
            filtered = filter_timeline_events(self._events, criteria)
        except (TypeError, ValueError) as exc:
            self.filter_status_var.set(f"Lỗi bộ lọc: {exc}")
            if show_errors:
                messagebox.showerror("Crow-Eye", str(exc))
            return

        rows = tuple(self._display_row(event) for event in filtered)
        self.table.set_rows(rows, id_key="timeline_event_id")
        self.filter_status_var.set(
            f"Hiển thị {len(rows)} / {len(self._events)} timeline events"
        )

    def clear_filters(self) -> None:
        for variable in (
            self.start_var,
            self.end_var,
            self.event_id_var,
            self.hostname_var,
            self.user_var,
            self.ip_var,
        ):
            variable.set("")
        self.apply_filters(show_errors=False)

    def _build_filters(self) -> None:
        frame = ttk.LabelFrame(self, text="Bộ lọc Timeline", padding=8)
        frame.pack(fill=tk.X, pady=(0, 8))
        self.start_var = tk.StringVar()
        self.end_var = tk.StringVar()
        self.event_id_var = tk.StringVar()
        self.hostname_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.ip_var = tk.StringVar()
        fields = (
            ("Từ (UTC)", self.start_var, 23),
            ("Đến (UTC)", self.end_var, 23),
            ("Event ID", self.event_id_var, 12),
            ("Hostname", self.hostname_var, 16),
            ("User", self.user_var, 16),
            ("IP", self.ip_var, 18),
        )
        for column, (label, variable, width) in enumerate(fields):
            ttk.Label(frame, text=label).grid(
                row=0,
                column=column,
                sticky="w",
                padx=(0, 6),
            )
            entry = ttk.Entry(frame, textvariable=variable, width=width)
            entry.grid(row=1, column=column, sticky="ew", padx=(0, 6))
            entry.bind("<Return>", lambda _event: self.apply_filters())
            frame.columnconfigure(column, weight=1)

        action_column = len(fields)
        ttk.Button(
            frame,
            text="Áp dụng",
            command=self.apply_filters,
        ).grid(row=1, column=action_column, padx=(4, 4))
        ttk.Button(
            frame,
            text="Xóa lọc",
            command=self.clear_filters,
        ).grid(row=1, column=action_column + 1, padx=(0, 4))
        self.filter_status_var = tk.StringVar(
            value="Hiển thị 0 / 0 timeline events"
        )
        ttk.Label(frame, textvariable=self.filter_status_var).grid(
            row=2,
            column=0,
            columnspan=action_column + 2,
            sticky="w",
            pady=(7, 0),
        )

    @staticmethod
    def _display_row(event: dict[str, Any]) -> dict[str, Any]:
        row = dict(event)
        details = event.get("details")
        details = details if isinstance(details, dict) else {}
        row["event_id"] = details.get("event_id")
        source_ip = str(details.get("source_ip") or "").strip()
        destination_ip = str(details.get("destination_ip") or "").strip()
        if source_ip and destination_ip and source_ip != destination_ip:
            row["ip"] = f"{source_ip} → {destination_ip}"
        else:
            row["ip"] = source_ip or destination_ip
        return row
