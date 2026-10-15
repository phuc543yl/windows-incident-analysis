"""Small modal progress dialog for explicit long-running operations."""

from __future__ import annotations

import tkinter as tk
from time import monotonic
from tkinter import ttk


class ProgressDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        message: str = "Đang xử lý...",
        *,
        title: str = "Crow-Eye",
    ) -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("640x380")
        self.minsize(500, 300)
        self.transient(parent)
        self._running = True
        self._started_at = monotonic()
        self._timer_id: str | None = None
        self.protocol("WM_DELETE_WINDOW", self._request_close)
        frame = ttk.Frame(self, padding=18)
        frame.pack(fill=tk.BOTH, expand=True)
        self.message_var = tk.StringVar(self, value=message)
        ttk.Label(
            frame,
            textvariable=self.message_var,
            wraplength=590,
        ).pack(anchor=tk.W, fill=tk.X)
        self.progress = ttk.Progressbar(
            frame,
            mode="indeterminate",
            length=320,
        )
        self.progress.pack(fill=tk.X, pady=(12, 0))
        self.elapsed_var = tk.StringVar(self)
        ttk.Label(frame, textvariable=self.elapsed_var).pack(anchor=tk.W, pady=8)
        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log = tk.Text(log_frame, height=10, wrap=tk.WORD, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.close_button = ttk.Button(
            frame,
            text="Đóng",
            command=self.close,
            state=tk.DISABLED,
        )
        self.close_button.pack(anchor=tk.E, pady=(12, 0))
        self.progress.start(10)
        self.set_message(message)
        self._update_elapsed()
        self.update_idletasks()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - 640) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - 380) // 2)
        self.geometry(f"+{x}+{y}")
        self.grab_set()

    def set_message(self, message: str) -> None:
        self.message_var.set(message)
        elapsed = int(monotonic() - self._started_at)
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, f"[{elapsed // 60:02d}:{elapsed % 60:02d}] {message}\n")
        self.log.configure(state=tk.DISABLED)
        self.log.see(tk.END)

    def _update_elapsed(self) -> None:
        elapsed = int(monotonic() - self._started_at)
        self.elapsed_var.set(f"Thời gian chạy: {elapsed // 60:02d}:{elapsed % 60:02d}")
        if self._running:
            self._timer_id = self.after(1000, self._update_elapsed)

    def finish(self, message: str = "Hoàn tất.", *, failed: bool = False) -> None:
        self._running = False
        self.progress.stop()
        if self._timer_id is not None:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        self._update_elapsed()
        if not failed:
            self.progress.configure(mode="determinate", value=100)
        self.set_message(message)
        self.close_button.configure(state=tk.NORMAL)

    def _request_close(self) -> None:
        if not self._running:
            self.close()

    def close(self) -> None:
        self.progress.stop()
        if self._timer_id is not None:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        self.grab_release()
        self.destroy()
