"""Evidence manifest, integrity, and bundle operations tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Iterable

from ui.components.data_table import Column, DataTable


class EvidenceTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_preserve: Callable[[], None],
        on_verify: Callable[[], None],
        on_bundle: Callable[[], None],
    ) -> None:
        super().__init__(parent, padding=10)
        self.summary_var = tk.StringVar(value="Chưa có manifest.")
        controls = ttk.Frame(self)
        controls.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(
            controls, text="Tạo manifest + SHA-256", command=on_preserve
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            controls, text="Kiểm tra toàn vẹn", command=on_verify
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            controls, text="Tạo Evidence Bundle", command=on_bundle
        ).pack(side=tk.LEFT)
        ttk.Label(
            controls,
            textvariable=self.summary_var,
            style="Muted.TLabel",
        ).pack(side=tk.RIGHT)
        self.table = DataTable(
            self,
            (
                Column("evidence_id", "Evidence ID", 190),
                Column("artifact_type", "Artifact", 120),
                Column("category", "Loại", 110),
                Column("stored_path", "Đường dẫn lưu", 280),
                Column("sha256", "SHA-256", 320),
                Column("size_bytes", "Kích thước", 100),
                Column("hostname", "Hostname", 130),
            ),
            height=18,
        )
        self.table.pack(fill=tk.BOTH, expand=True)

    def set_manifest(self, manifest: dict[str, Any]) -> None:
        items = manifest.get("evidence_items", [])
        self.table.set_rows(items, id_key="evidence_id")
        self.summary_var.set(
            f"{len(items)} evidence | "
            f"{manifest.get('total_size_bytes', 0)} bytes | "
            f"{manifest.get('hash_algorithm', 'sha256')}"
        )

    def set_verification(self, result: dict[str, Any]) -> None:
        self.summary_var.set(
            f"Toàn vẹn: {'Đạt' if result.get('success') else 'Không đạt'} | "
            f"Khớp {result.get('matched_count', 0)}/"
            f"{result.get('item_count', 0)}"
        )
