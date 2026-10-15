"""Story, MITRE, entity pivot, baseline, notes, and checklist."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, ttk
from typing import Any

from ui.components.data_table import Column, DataTable


class InvestigateTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_add_note: Callable[[str], None],
        on_save_checklist: Callable[[list[dict[str, Any]]], None],
        on_pivot: Callable[[str, str], None],
        on_capture_baseline: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent, padding=10)
        self.on_add_note = on_add_note
        self.on_save_checklist = on_save_checklist
        self.on_pivot = on_pivot
        self._checklist_items: list[dict[str, Any]] = []
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        story = ttk.Frame(notebook, padding=6)
        self.story = DataTable(
            story,
            (
                Column("order", "#", 40),
                Column("timestamp", "Thời điểm", 170),
                Column("title", "Mốc", 260),
                Column("summary", "Tóm tắt", 420),
                Column("incident_id", "Incident", 180),
            ),
            height=12,
        )
        self.story.pack(fill=tk.BOTH, expand=True)
        notebook.add(story, text="Story")

        mitre = ttk.Frame(notebook, padding=6)
        self.mitre = DataTable(
            mitre,
            (
                Column("technique_id", "Technique", 110),
                Column("technique_name", "Tên", 240),
                Column("tactics", "Tactic", 220),
                Column("alert_count", "Alert", 70),
                Column("finding_count", "Finding", 80),
            ),
            height=12,
        )
        self.mitre.pack(fill=tk.BOTH, expand=True)
        notebook.add(mitre, text="MITRE")

        pivot = ttk.Frame(notebook, padding=6)
        filters = ttk.Frame(pivot)
        filters.pack(fill=tk.X, pady=(0, 6))
        self.entity_type = tk.StringVar(value="user")
        self.entity_value = tk.StringVar()
        ttk.Combobox(
            filters,
            textvariable=self.entity_type,
            values=("user", "ip", "process", "file"),
            state="readonly",
            width=12,
        ).pack(side=tk.LEFT)
        ttk.Entry(filters, textvariable=self.entity_value, width=40).pack(
            side=tk.LEFT,
            padx=6,
        )
        ttk.Button(filters, text="Lọc thực thể", command=self._pivot).pack(side=tk.LEFT)
        self.entities_hint = tk.StringVar(value="Chưa có thực thể.")
        ttk.Label(filters, textvariable=self.entities_hint, style="Muted.TLabel").pack(
            side=tk.LEFT,
            padx=8,
        )
        self.pivot_table = DataTable(
            pivot,
            (
                Column("timestamp", "Thời điểm", 170),
                Column("event_id", "Event", 70),
                Column("user", "User", 120),
                Column("source_ip", "IP", 130),
                Column("process_name", "Process", 140),
                Column("summary", "Tóm tắt", 360),
            ),
            height=11,
        )
        self.pivot_table.pack(fill=tk.BOTH, expand=True)
        notebook.add(pivot, text="Pivot")

        baseline = ttk.Frame(notebook, padding=6)
        baseline_actions = ttk.Frame(baseline)
        baseline_actions.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(
            baseline_actions,
            text="Lưu baseline T0",
            command=on_capture_baseline,
            state=tk.NORMAL if on_capture_baseline else tk.DISABLED,
        ).pack(side=tk.LEFT)
        self.baseline_hint = tk.StringVar(
            value="Lưu T0 trước thử nghiệm; phân tích dữ liệu T1 để xem thay đổi."
        )
        ttk.Label(
            baseline_actions, textvariable=self.baseline_hint, wraplength=760
        ).pack(side=tk.LEFT, padx=8)
        self.baseline = DataTable(
            baseline,
            (
                Column("category", "Nhóm", 110),
                Column("identifier", "Đối tượng", 220),
                Column("before", "Trước", 200),
                Column("after", "Sau", 200),
                Column("summary", "Tóm tắt", 280),
            ),
            height=12,
        )
        self.baseline.pack(fill=tk.BOTH, expand=True)
        notebook.add(baseline, text="Baseline")

        notes = ttk.Frame(notebook, padding=6)
        self.notes = DataTable(
            notes,
            (
                Column("timestamp", "Thời điểm", 180),
                Column("actor", "Người ghi", 120),
                Column("text", "Nội dung", 620),
            ),
            height=9,
        )
        self.notes.pack(fill=tk.BOTH, expand=True)
        note_row = ttk.Frame(notes)
        note_row.pack(fill=tk.X, pady=(8, 0))
        self.note_var = tk.StringVar()
        ttk.Entry(note_row, textvariable=self.note_var).pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
        )
        ttk.Button(note_row, text="Thêm ghi chú", command=self._add_note).pack(
            side=tk.LEFT,
            padx=(8, 0),
        )
        notebook.add(notes, text="Ghi chú")

        check = ttk.Frame(notebook, padding=6)
        self.checklist_box = tk.Listbox(check, height=12, selectmode=tk.MULTIPLE)
        self.checklist_box.pack(fill=tk.BOTH, expand=True)
        ttk.Button(
            check,
            text="Lưu checklist (các mục đang chọn = đã xong)",
            command=self._save_checklist,
        ).pack(anchor=tk.W, pady=(8, 0))
        notebook.add(check, text="Checklist")

    def set_investigation(self, data: dict[str, Any]) -> None:
        story = (data.get("story") or {}).get("milestones") or data.get(
            "story_rows",
            [],
        )
        if isinstance(data.get("story"), list):
            story = data["story"]
        self.story.set_rows(story, id_key="order")
        mitre = (data.get("mitre") or {}).get("techniques") or []
        self.mitre.set_rows(mitre, id_key="technique_id")
        baseline = (data.get("baseline") or {}).get("changes") or []
        self.baseline.set_rows(baseline, id_key="identifier")
        baseline_notes = (data.get("baseline") or {}).get("notes") or []
        self.baseline_hint.set(
            " ".join(baseline_notes)
            or "Lưu T0 trước thử nghiệm; phân tích dữ liệu T1 để xem thay đổi."
        )
        self.notes.set_rows(data.get("notes") or [], id_key="timestamp")
        entities = data.get("entities") or {}
        self.entities_hint.set(
            "User: "
            + ", ".join((entities.get("users") or [])[:6])
            + " | IP: "
            + ", ".join((entities.get("ips") or [])[:6])
        )
        self._checklist_items = list(data.get("checklist") or [])
        self.checklist_box.delete(0, tk.END)
        for item in self._checklist_items:
            mark = "[x] " if item.get("done") else "[ ] "
            self.checklist_box.insert(tk.END, mark + str(item.get("text", "")))
            if item.get("done"):
                self.checklist_box.selection_set(tk.END)

    def set_pivot_rows(self, rows: list[dict[str, Any]]) -> None:
        self.pivot_table.set_rows(rows, id_key="record_id")

    def _add_note(self) -> None:
        text = self.note_var.get().strip()
        if not text:
            messagebox.showinfo("Crow-Eye", "Hãy nhập nội dung ghi chú.")
            return
        self.on_add_note(text)
        self.note_var.set("")

    def _save_checklist(self) -> None:
        selected = set(self.checklist_box.curselection())
        items = []
        for index, item in enumerate(self._checklist_items):
            updated = dict(item)
            updated["done"] = index in selected
            items.append(updated)
        self.on_save_checklist(items)

    def _pivot(self) -> None:
        self.on_pivot(self.entity_type.get(), self.entity_value.get().strip())
