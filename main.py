"""Desktop entry point for the Windows incident analysis dashboard."""

from __future__ import annotations

import sys
from collections.abc import Callable


def _load_dashboard() -> Callable[[], int | None]:
    """Load the UI lazily so the project can be bootstrapped in stages."""
    try:
        from ui.main_window import run_dashboard
    except ModuleNotFoundError as exc:
        if exc.name not in {"ui", "ui.main_window"}:
            raise
        raise RuntimeError(
            "Dashboard chưa được triển khai. "
            "Hãy tạo ui/main_window.py và hàm run_dashboard()."
        ) from exc

    if not callable(run_dashboard):
        raise RuntimeError("ui.main_window.run_dashboard phải là một hàm.")
    return run_dashboard


def main() -> int:
    """Start the Tkinter dashboard and return a process exit code."""
    try:
        run_dashboard = _load_dashboard()
        result = run_dashboard()
        return int(result) if result is not None else 0
    except KeyboardInterrupt:
        print("\nĐã dừng Dashboard.", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"Lỗi khởi động: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - last-resort entry-point guard
        print(f"Lỗi không mong muốn khi khởi động Dashboard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
