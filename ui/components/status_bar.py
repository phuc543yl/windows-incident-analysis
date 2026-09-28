"""Application status text and indeterminate activity indicator."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ui.theme import AMBER, NAVY, TEAL


class StatusBar(ttk.Frame):
    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent, padding=(14, 6), style="Status.TFrame")
        self.message_var = tk.StringVar(value="Sẵn sàng")
        self.case_var = tk.StringVar(value="Chưa chọn Case")
        self._pulse = 0
        self._busy = False
        self.dot = tk.Canvas(
            self,
            width=14,
            height=14,
            bg=NAVY,
            highlightthickness=0,
        )
        self.dot.pack(side=tk.LEFT, padx=(0, 8))
        self._oval = self.dot.create_oval(2, 2, 12, 12, fill=TEAL, outline="")
        ttk.Label(
            self,
            textvariable=self.message_var,
            style="Status.TLabel",
        ).pack(side=tk.LEFT)
        ttk.Label(
            self,
            textvariable=self.case_var,
            style="Status.TLabel",
        ).pack(side=tk.RIGHT)
        self.progress = ttk.Progressbar(
            self,
            mode="indeterminate",
            length=140,
        )
        self.progress.pack(side=tk.RIGHT, padx=(0, 12))
        self.after(400, self._animate_dot)

    def set_message(self, message: str) -> None:
        self.message_var.set(str(message).strip() or "Sẵn sàng")

    def set_case(self, case_id: str | None) -> None:
        self.case_var.set(case_id or "Chưa chọn Case")

    def set_busy(self, busy: bool, message: str | None = None) -> None:
        self._busy = busy
        if message is not None:
            self.set_message(message)
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    def _animate_dot(self) -> None:
        self._pulse = (self._pulse + 1) % 2
        color = AMBER if self._busy and self._pulse else TEAL
        if self._busy and not self._pulse:
            color = "#0F766E"
        self.dot.itemconfigure(self._oval, fill=color)
        self.after(450, self._animate_dot)
