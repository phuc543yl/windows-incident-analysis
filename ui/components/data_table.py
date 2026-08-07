"""Scrollable Treeview wrapper for dictionaries and model records."""

from __future__ import annotations

import json
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class Column:
    key: str
    title: str
    width: int = 140
    anchor: str = tk.W


class DataTable(ttk.Frame):
    def __init__(
        self,
        parent: tk.Misc,
        columns: Iterable[Column],
        *,
        height: int = 10,
        selectmode: str = "browse",
    ) -> None:
        super().__init__(parent)
        self.columns = tuple(columns)
        if not self.columns:
            raise ValueError("DataTable phải có ít nhất một cột.")
        self._records: dict[str, dict[str, Any]] = {}

        column_ids = tuple(column.key for column in self.columns)
        self.tree = ttk.Treeview(
            self,
            columns=column_ids,
            show="headings",
            height=height,
            selectmode=selectmode,
        )
        vertical = ttk.Scrollbar(
            self,
            orient=tk.VERTICAL,
            command=self.tree.yview,
        )
        horizontal = ttk.Scrollbar(
            self,
            orient=tk.HORIZONTAL,
            command=self.tree.xview,
        )
        self.tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )
        for column in self.columns:
            self.tree.heading(column.key, text=column.title)
            self.tree.column(
                column.key,
                width=column.width,
                minwidth=60,
                anchor=column.anchor,
                stretch=True,
            )
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def set_rows(
        self,
        records: Iterable[dict[str, Any]],
        *,
        id_key: str | None = None,
    ) -> None:
        self.clear()
        for index, record in enumerate(records):
            item = dict(record)
            preferred = str(item.get(id_key, "")) if id_key else ""
            iid = (
                preferred
                if preferred and preferred not in self._records
                else str(index)
            )
            self._records[iid] = item
            self.tree.insert(
                "",
                tk.END,
                iid=iid,
                values=tuple(
                    normalize_cell(item.get(column.key))
                    for column in self.columns
                ),
            )

    def clear(self) -> None:
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)
        self._records.clear()

    def selected_record(self) -> dict[str, Any] | None:
        selection = self.tree.selection()
        if not selection:
            return None
        record = self._records.get(selection[0])
        return dict(record) if record is not None else None

    def bind_activate(self, callback) -> None:
        self.tree.bind("<Double-1>", callback)
        self.tree.bind("<Return>", callback)


def normalize_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)
