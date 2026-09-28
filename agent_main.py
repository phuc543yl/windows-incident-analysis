"""Command-line entry point for the Windows collection Agent API."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_CONFIG = Path("config/agent.json")


def build_parser() -> argparse.ArgumentParser:
    """Create the Agent command-line parser."""
    parser = argparse.ArgumentParser(
        description="Khởi động Agent API phục vụ thu thập bằng chứng Windows.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Địa chỉ lắng nghe (mặc định: {DEFAULT_HOST}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Cổng Agent API (mặc định: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"Đường dẫn cấu hình Agent (mặc định: {DEFAULT_CONFIG}).",
    )
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        raise ValueError("Port phải nằm trong khoảng 1-65535.")
    if not args.host.strip():
        raise ValueError("Host không được để trống.")
    if not args.config.is_file():
        raise FileNotFoundError(
            f"Không tìm thấy cấu hình Agent: {args.config}. "
            "Hãy tạo config/agent.json trước khi chạy Agent."
        )


def _create_app(config_path: Path) -> Any:
    """Load the Agent application factory lazily."""
    try:
        from agent.app import create_app
    except ModuleNotFoundError as exc:
        if exc.name not in {"agent", "agent.app"}:
            raise
        raise RuntimeError(
            "Agent chưa được triển khai. "
            "Hãy tạo agent/app.py và hàm create_app(config_path)."
        ) from exc

    if not callable(create_app):
        raise RuntimeError("agent.app.create_app phải là một hàm.")
    return create_app(config_path=config_path)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate settings and run the Agent without Flask's debug reloader."""
    from common.lab_env import load_lab_env

    load_lab_env()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        _validate_args(args)
        app = _create_app(args.config.resolve())
        app.run(
            host=args.host,
            port=args.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
        return 0
    except KeyboardInterrupt:
        print("\nĐã dừng Agent.", file=sys.stderr)
        return 130
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"Lỗi khởi động Agent: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - last-resort entry-point guard
        print(f"Lỗi không mong muốn của Agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
