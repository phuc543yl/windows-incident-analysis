"""Application status text and indeterminate activity indicator."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class StatusBar(ttk.Frame):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, padding=(8, 4))
        self.message_var = tk.StringVar(value="Sẵn sàng")
        self.case_var = tk.StringVar(value="Chưa chọn Case")
        ttk.Label(self, textvariable=self.message_var).pack(side=tk.LEFT)
        ttk.Label(
            self,
            textvariable=self.case_var,
            style="Muted.TLabel",
        ).pack(side=tk.RIGHT)
        self.progress = ttk.Progressbar(
            self,
            mode="indeterminate",
            length=110,
        )
        self.progress.pack(side=tk.RIGHT, padx=(0, 12))

    def set_message(self, message: str) -> None:
        self.message_var.set(str(message).strip() or "Sẵn sàng")

    def set_case(self, case_id: str | None) -> None:
        self.case_var.set(case_id or "Chưa chọn Case")

    def set_busy(self, busy: bool, message: str | None = None) -> None:
        if message is not None:
            self.set_message(message)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()
