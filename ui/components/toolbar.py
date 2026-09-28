"""Primary action toolbar shared across dashboard tabs."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from ui.theme import ASSETS, load_photo


class Toolbar(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_new: Callable[[], None],
        on_refresh: Callable[[], None],
        on_collect: Callable[[], None],
        on_analyze: Callable[[], None],
        on_report: Callable[[], None],
    ) -> None:
        super().__init__(parent, padding=(12, 8), style="Toolbar.TFrame")
        self.case_var = tk.StringVar(value="Chưa chọn Case")
        self._logo = load_photo(ASSETS / "croweye_logo.png", width=32, height=32)
        if self._logo is not None:
            ttk.Label(self, image=self._logo, style="Toolbar.TLabel").pack(
                side=tk.LEFT,
                padx=(0, 10),
            )
        ttk.Label(self, text="Crow-Eye", style="Toolbar.TLabel").pack(
            side=tk.LEFT,
            padx=(0, 16),
        )
        actions = (
            ("＋  Case mới", on_new),
            ("↻  Làm mới", on_refresh),
            ("↓  Thu thập", on_collect),
            ("◈  Phân tích", on_analyze),
            ("▤  Báo cáo", on_report),
        )
        for text, command in actions:
            ttk.Button(self, text=text, command=command).pack(
                side=tk.LEFT,
                padx=(0, 8),
            )
        ttk.Label(
            self,
            textvariable=self.case_var,
            style="Toolbar.TLabel",
        ).pack(side=tk.RIGHT, padx=(8, 4))

    def set_case(self, case_id: str | None) -> None:
        self.case_var.set(
            f"CASE  {case_id}" if case_id else "Chưa chọn Case"
        )
