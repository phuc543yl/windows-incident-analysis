"""Agent connection information and health-check tab."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable


class AgentTab(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_health_check: Callable[[], None],
    ) -> None:
        super().__init__(parent, padding=16)
        self.agent_id_var = tk.StringVar(value="-")
        self.endpoint_var = tk.StringVar(value="-")
        self.auth_var = tk.StringVar(value="-")
        self.status_var = tk.StringVar(value="Chưa kiểm tra")
        card = ttk.LabelFrame(self, text="Agent API", padding=14)
        card.pack(fill=tk.X)
        rows = (
            ("Agent ID", self.agent_id_var),
            ("Endpoint", self.endpoint_var),
            ("Xác thực", self.auth_var),
            ("Trạng thái", self.status_var),
        )
        for row, (label, variable) in enumerate(rows):
            ttk.Label(card, text=label).grid(
                row=row, column=0, sticky="w", pady=4
            )
            ttk.Label(card, textvariable=variable).grid(
                row=row, column=1, sticky="w", padx=(18, 0), pady=4
            )
        ttk.Button(
            card,
            text="Kiểm tra kết nối",
            command=on_health_check,
        ).grid(row=len(rows), column=0, columnspan=2, sticky="w", pady=(12, 0))
        ttk.Label(
            self,
            text=(
                "Token không được nhập hoặc lưu trong giao diện. "
                "AgentClient đọc token từ biến môi trường đã cấu hình."
            ),
            style="Muted.TLabel",
            wraplength=760,
        ).pack(anchor=tk.W, pady=(12, 0))

    def set_configuration(self, config: dict[str, Any]) -> None:
        agent = config.get("agent", {})
        authentication = config.get("authentication", {})
        transport = config.get("transport", {})
        scheme = "https" if transport.get("https_enabled") else "http"
        self.agent_id_var.set(agent.get("agent_id", "-"))
        self.endpoint_var.set(
            f"{scheme}://{agent.get('host', '127.0.0.1')}:"
            f"{agent.get('port', 8765)}"
        )
        self.auth_var.set(
            "Bật (biến môi trường)"
            if authentication.get("enabled")
            else "Tắt"
        )

    def set_health(self, result: dict[str, Any]) -> None:
        status = result.get("status", "unknown")
        agent_id = result.get("agent_id")
        self.status_var.set(
            f"{status} — {agent_id}" if agent_id else str(status)
        )
