"""Crow-Eye visual theme: colors, ttk styles, and image helpers."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk

NAVY = "#0B1F33"
NAVY_2 = "#14324C"
TEAL = "#14B8A6"
TEAL_DARK = "#0F766E"
AMBER = "#F5B942"
SURFACE = "#F3F6FB"
CARD = "#FFFFFF"
INK = "#122033"
MUTED = "#5C6D7A"
LINE = "#D7E0EA"

ASSETS = Path(__file__).resolve().parent / "assets"


def apply_theme(root: tk.Misc) -> ttk.Style:
    """Apply a high-contrast desktop theme. Clam is required for custom colors."""
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    root.configure(background=SURFACE)
    style.configure(".", background=SURFACE, foreground=INK, font=("Segoe UI", 10))
    style.configure("TFrame", background=SURFACE)
    style.configure("TLabel", background=SURFACE, foreground=INK, font=("Segoe UI", 10))
    style.configure("Muted.TLabel", background=SURFACE, foreground=MUTED)
    style.configure(
        "TLabelframe",
        background=SURFACE,
        foreground=NAVY,
        bordercolor=LINE,
        relief="solid",
    )
    style.configure(
        "TLabelframe.Label",
        background=SURFACE,
        foreground=NAVY,
        font=("Segoe UI", 10, "bold"),
    )
    style.configure(
        "TButton",
        background=TEAL,
        foreground="#042F2E",
        bordercolor=TEAL_DARK,
        focusthickness=0,
        focuscolor=TEAL,
        padding=(12, 7),
        font=("Segoe UI", 10, "bold"),
    )
    style.map(
        "TButton",
        background=[("active", "#2DD4BF"), ("pressed", TEAL_DARK)],
        foreground=[("disabled", MUTED)],
    )
    style.configure(
        "TNotebook",
        background=SURFACE,
        bordercolor=LINE,
        tabmargins=(6, 6, 6, 0),
    )
    style.configure(
        "TNotebook.Tab",
        background="#E2EAF3",
        foreground=NAVY,
        padding=(14, 8),
        font=("Segoe UI", 9, "bold"),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", TEAL), ("active", "#CCFBF1")],
        foreground=[("selected", "#042F2E")],
    )
    style.configure(
        "Treeview",
        background=CARD,
        fieldbackground=CARD,
        foreground=INK,
        rowheight=28,
        bordercolor=LINE,
        font=("Segoe UI", 10),
    )
    style.configure(
        "Treeview.Heading",
        background=NAVY,
        foreground="#FFFFFF",
        relief="flat",
        font=("Segoe UI", 9, "bold"),
    )
    style.map(
        "Treeview",
        background=[("selected", "#CCFBF1")],
        foreground=[("selected", NAVY)],
    )
    style.configure("TEntry", fieldbackground=CARD, padding=4)
    style.configure("TCombobox", fieldbackground=CARD, padding=4)
    style.configure(
        "Horizontal.TProgressbar",
        background=TEAL,
        troughcolor=NAVY_2,
        bordercolor=NAVY,
        lightcolor=TEAL,
        darkcolor=TEAL,
    )
    style.configure("Status.TFrame", background=NAVY)
    style.configure(
        "Status.TLabel",
        background=NAVY,
        foreground="#E6F4F1",
        font=("Segoe UI", 9),
    )
    style.configure(
        "Toolbar.TFrame",
        background=NAVY_2,
    )
    style.configure(
        "Toolbar.TLabel",
        background=NAVY_2,
        foreground=AMBER,
        font=("Segoe UI", 10, "bold"),
    )
    return style


def load_photo(path: Path, *, width: int, height: int) -> tk.PhotoImage | None:
    """Resize a PNG for Tk. Returns None when the asset or Pillow is missing."""
    if not path.is_file():
        return None
    try:
        from PIL import Image, ImageTk
    except ImportError:
        try:
            return tk.PhotoImage(file=str(path))
        except tk.TclError:
            return None
    image = Image.open(path).convert("RGBA")
    image.thumbnail((width, height), Image.Resampling.LANCZOS)
    return ImageTk.PhotoImage(image)
