"""Small modal progress dialog for explicit long-running operations."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class ProgressDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        message: str = "Đang xử lý...",
    ) -> None:
        super().__init__(parent)
        self.title("Crow-Eye")
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        frame = ttk.Frame(self, padding=18)
        frame.pack(fill=tk.BOTH, expand=True)
        self.message_var = tk.StringVar(value=message)
        ttk.Label(frame, textvariable=self.message_var).pack(anchor=tk.W)
        self.progress = ttk.Progressbar(
            frame,
            mode="indeterminate",
            length=320,
        )
        self.progress.pack(fill=tk.X, pady=(12, 0))
        self.progress.start(10)
        self.grab_set()

    def set_message(self, message: str) -> None:
        self.message_var.set(message)
        self.update_idletasks()

    def close(self) -> None:
        self.progress.stop()
        self.grab_release()
        self.destroy()
