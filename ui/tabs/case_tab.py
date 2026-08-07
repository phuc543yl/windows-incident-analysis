"""Case creation, selection, update, and closure tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Callable, Iterable

from ui.components.data_table import Column, DataTable


class CaseTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        profile_ids: Iterable[str],
        on_create: Callable[[dict[str, Any]], None],
        on_open: Callable[[str], None],
        on_update: Callable[[dict[str, Any]], None],
        on_close: Callable[[str], None],
    ) -> None:
        super().__init__(parent, padding=10)
        self.on_create = on_create
        self.on_open = on_open
        self.on_update = on_update
        self.on_close = on_close
        self.current_case_id: str | None = None

        self.variables = {
            "title": tk.StringVar(),
            "target_hostname": tk.StringVar(),
            "mode": tk.StringVar(value="local"),
            "profile_id": tk.StringVar(value="general_investigation"),
            "target_ip_addresses": tk.StringVar(),
            "target_agent_id": tk.StringVar(),
            "tags": tk.StringVar(),
        }
        form = ttk.LabelFrame(self, text="Thông tin Case", padding=10)
        form.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        fields = (
            ("Tiêu đề", "title"),
            ("Hostname", "target_hostname"),
            ("Địa chỉ IP", "target_ip_addresses"),
            ("Agent ID", "target_agent_id"),
            ("Tags", "tags"),
        )
        for row, (label, key) in enumerate(fields):
            ttk.Label(form, text=label).grid(
                row=row,
                column=0,
                sticky="w",
                pady=3,
            )
            ttk.Entry(form, textvariable=self.variables[key], width=42).grid(
                row=row,
                column=1,
                sticky="ew",
                pady=3,
            )
        ttk.Label(form, text="Chế độ").grid(
            row=5, column=0, sticky="w", pady=3
        )
        ttk.Combobox(
            form,
            textvariable=self.variables["mode"],
            values=("local", "agent"),
            state="readonly",
        ).grid(row=5, column=1, sticky="ew", pady=3)
        ttk.Label(form, text="Profile").grid(
            row=6, column=0, sticky="w", pady=3
        )
        ttk.Combobox(
            form,
            textvariable=self.variables["profile_id"],
            values=tuple(profile_ids),
            state="readonly",
        ).grid(row=6, column=1, sticky="ew", pady=3)
        ttk.Label(form, text="Mô tả").grid(
            row=7, column=0, sticky="nw", pady=3
        )
        self.description = tk.Text(form, height=4, width=42, wrap="word")
        self.description.grid(row=7, column=1, sticky="ew", pady=3)
        ttk.Label(form, text="Giả thuyết").grid(
            row=8, column=0, sticky="nw", pady=3
        )
        self.hypothesis = tk.Text(form, height=4, width=42, wrap="word")
        self.hypothesis.grid(row=8, column=1, sticky="ew", pady=3)
        form.columnconfigure(1, weight=1)

        actions = ttk.Frame(form)
        actions.grid(row=9, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        ttk.Button(
            actions, text="Tạo Case", command=self._create
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            actions, text="Cập nhật", command=self._update
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            actions, text="Đóng Case", command=self._close
        ).pack(side=tk.LEFT)

        listing = ttk.LabelFrame(self, text="Danh sách Case", padding=8)
        listing.grid(row=0, column=1, sticky="nsew")
        self.table = DataTable(
            listing,
            (
                Column("case_id", "Case ID", 165),
                Column("title", "Tiêu đề", 220),
                Column("mode", "Mode", 75),
                Column("status", "Trạng thái", 90),
                Column("updated_at", "Cập nhật", 165),
            ),
            height=18,
        )
        self.table.pack(fill=tk.BOTH, expand=True)
        ttk.Button(
            listing,
            text="Mở Case đã chọn",
            command=self._open_selected,
        ).pack(anchor=tk.E, pady=(8, 0))
        self.table.bind_activate(lambda _event: self._open_selected())

        self.columnconfigure(0, weight=2)
        self.columnconfigure(1, weight=3)
        self.rowconfigure(0, weight=1)

    def set_cases(self, cases: Iterable[dict[str, Any]]) -> None:
        self.table.set_rows(cases, id_key="case_id")

    def set_context(self, context: dict[str, Any]) -> None:
        case = context["case"]
        target = context["target"]
        self.current_case_id = case["case_id"]
        for key in ("title", "mode", "profile_id", "tags"):
            value = case.get(key, "")
            if isinstance(value, list):
                value = ", ".join(value)
            self.variables[key].set(value)
        self.variables["target_hostname"].set(target.get("hostname", ""))
        self.variables["target_ip_addresses"].set(
            ", ".join(target.get("ip_addresses", []))
        )
        self.variables["target_agent_id"].set(target.get("agent_id") or "")
        _set_text(self.description, case.get("description", ""))
        _set_text(self.hypothesis, case.get("hypothesis", ""))

    def show_new_form(self) -> None:
        self.current_case_id = None
        for key, variable in self.variables.items():
            variable.set(
                "local"
                if key == "mode"
                else (
                    "general_investigation"
                    if key == "profile_id"
                    else ""
                )
            )
        _set_text(self.description, "")
        _set_text(self.hypothesis, "")
        self.variables["title"].set("Điều tra sự cố Windows")

    def _create(self) -> None:
        values = {
            "title": self.variables["title"].get().strip(),
            "target_hostname": self.variables[
                "target_hostname"
            ].get().strip(),
            "mode": self.variables["mode"].get(),
            "profile_id": self.variables["profile_id"].get(),
            "description": self.description.get("1.0", "end-1c").strip(),
            "hypothesis": self.hypothesis.get("1.0", "end-1c").strip(),
            "target_ip_addresses": _split_values(
                self.variables["target_ip_addresses"].get()
            ),
            "target_agent_id": (
                self.variables["target_agent_id"].get().strip() or None
            ),
            "tags": _split_values(self.variables["tags"].get()),
        }
        self.on_create(values)

    def _update(self) -> None:
        self.on_update(
            {
                "title": self.variables["title"].get().strip(),
                "description": self.description.get(
                    "1.0", "end-1c"
                ).strip(),
                "hypothesis": self.hypothesis.get(
                    "1.0", "end-1c"
                ).strip(),
                "tags": _split_values(self.variables["tags"].get()),
            }
        )

    def _open_selected(self) -> None:
        record = self.table.selected_record()
        if record is None:
            messagebox.showinfo("Crow-Eye", "Hãy chọn một Case.")
            return
        self.on_open(record["case_id"])

    def _close(self) -> None:
        if not self.current_case_id:
            messagebox.showinfo("Crow-Eye", "Chưa có Case đang mở.")
            return
        if not messagebox.askyesno(
            "Đóng Case",
            f"Đóng {self.current_case_id}? Case sẽ không thể thu thập thêm.",
        ):
            return
        conclusion = simpledialog.askstring(
            "Kết luận",
            "Kết luận khi đóng Case:",
            parent=self,
        )
        self.on_close(conclusion or "")


def _split_values(value: str) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for item in value.replace(";", ",").split(",")
        if item.strip()
    )


def _set_text(widget: tk.Text, value: Any) -> None:
    widget.delete("1.0", tk.END)
    widget.insert("1.0", str(value or ""))
