"""CLI entry point for case, collection, analysis, and reporting workflows."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


class CliDependencyError(RuntimeError):
    """Raised when a workflow module has not been implemented yet."""


def _json_default(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, (Path, Enum)):
        return value.value if isinstance(value, Enum) else str(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return vars(value)
    return str(value)


def _print_result(result: Any) -> None:
    """Print service results in a stable, readable JSON form."""
    if result is None:
        return
    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            default=_json_default,
        )
    )


def _load_service(
    module_name: str,
    class_name: str,
    root: str | Path | None = None,
) -> Any:
    """Import a service only when its command is executed."""
    try:
        module = __import__(module_name, fromlist=[class_name])
    except ModuleNotFoundError as exc:
        missing_root = module_name.split(".", maxsplit=1)[0]
        if exc.name not in {missing_root, module_name}:
            raise
        raise CliDependencyError(
            f"Chưa có module {module_name}. "
            "Hãy triển khai module này trước khi dùng lệnh tương ứng."
        ) from exc

    service_class = getattr(module, class_name, None)
    if service_class is None:
        raise CliDependencyError(f"Không tìm thấy {class_name} trong {module_name}.")
    return service_class(root) if root is not None else service_class()


def _add_case_commands(subparsers: Any) -> None:
    case_parser = subparsers.add_parser("case", help="Quản lý hồ sơ điều tra.")
    case_subparsers = case_parser.add_subparsers(
        dest="case_command",
        required=True,
    )

    create_parser = case_subparsers.add_parser("create", help="Tạo Case mới.")
    create_parser.add_argument("--title", required=True, help="Tên vụ việc.")
    create_parser.add_argument(
        "--target",
        required=True,
        help="Hostname hoặc định danh máy cần điều tra.",
    )
    create_parser.add_argument(
        "--mode",
        choices=("local", "agent"),
        default="local",
        help="Chế độ thu thập.",
    )
    create_parser.add_argument(
        "--profile",
        default="general_investigation",
        help="Investigation profile.",
    )
    create_parser.add_argument(
        "--description",
        default="",
        help="Mô tả hoặc giả thuyết điều tra ban đầu.",
    )
    create_parser.set_defaults(handler=_handle_case_create)

    list_parser = case_subparsers.add_parser("list", help="Liệt kê Case.")
    list_parser.add_argument(
        "--status",
        choices=("open", "closed", "all"),
        default="all",
        help="Lọc theo trạng thái.",
    )
    list_parser.set_defaults(handler=_handle_case_list)

    show_parser = case_subparsers.add_parser("show", help="Xem một Case.")
    show_parser.add_argument("case_id", help="Mã Case.")
    show_parser.set_defaults(handler=_handle_case_show)

    close_parser = case_subparsers.add_parser("close", help="Đóng một Case.")
    close_parser.add_argument("case_id", help="Mã Case.")
    close_parser.add_argument(
        "--conclusion",
        default="",
        help="Kết luận ngắn của chuyên viên.",
    )
    close_parser.set_defaults(handler=_handle_case_close)


def _add_workflow_commands(subparsers: Any) -> None:
    collect_parser = subparsers.add_parser(
        "collect",
        help="Thu thập bằng chứng theo Collection Plan của Case.",
    )
    collect_parser.add_argument("case_id", help="Mã Case.")
    collect_parser.add_argument(
        "--mode",
        choices=("local", "agent"),
        help="Ghi đè chế độ lưu trong Case.",
    )
    collect_parser.add_argument(
        "--agent-id",
        help="Agent ID khi sử dụng Agent Mode.",
    )
    collect_parser.set_defaults(handler=_handle_collect)

    preserve_parser = subparsers.add_parser(
        "preserve",
        help="Lập manifest và hash SHA-256 cho bằng chứng đã thu thập.",
    )
    preserve_parser.add_argument("case_id", help="Mã Case.")
    preserve_parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Chủ động lập lại manifest đã tồn tại.",
    )
    preserve_parser.set_defaults(handler=_handle_preserve)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Kiểm tra hash và tính toàn vẹn bằng chứng.",
    )
    verify_parser.add_argument("case_id", help="Mã Case.")
    verify_parser.set_defaults(handler=_handle_verify)

    process_parser = subparsers.add_parser(
        "process",
        help="Chạy DFIR tools, parse output và tạo timeline chuẩn hóa.",
    )
    process_parser.add_argument("case_id", help="Mã Case.")
    process_parser.add_argument(
        "--tool",
        dest="tools",
        action="append",
        help=(
            "Chỉ chạy tool này; có thể truyền nhiều lần. "
            "Mặc định dùng danh sách trong investigation profile."
        ),
    )
    process_parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Dừng ngay khi một tool gặp lỗi.",
    )
    process_parser.set_defaults(handler=_handle_process)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Chạy analyzer, detection rule và correlation.",
    )
    analyze_parser.add_argument("case_id", help="Mã Case.")
    analyze_parser.set_defaults(handler=_handle_analyze)

    report_parser = subparsers.add_parser(
        "report",
        help="Xuất báo cáo điều tra.",
    )
    report_parser.add_argument("case_id", help="Mã Case.")
    report_parser.add_argument(
        "--format",
        dest="formats",
        action="append",
        choices=("html", "pdf", "json", "csv"),
        help="Có thể truyền nhiều lần; mặc định xuất html và json.",
    )
    report_parser.set_defaults(handler=_handle_report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfir_cli",
        description="CLI của bộ công cụ hỗ trợ phân tích sự cố Windows.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Crow-Eye 1.0.0",
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="Project root; mặc định là thư mục chứa mã nguồn.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_case_commands(subparsers)
    _add_workflow_commands(subparsers)
    return parser


def _handle_case_create(args: argparse.Namespace) -> Any:
    service = _load_service(
        "case_management.case_service",
        "CaseService",
        args.root,
    )
    return service.create_case(
        title=args.title,
        target_hostname=args.target,
        mode=args.mode,
        profile_id=args.profile,
        description=args.description,
    )


def _handle_case_list(args: argparse.Namespace) -> Any:
    service = _load_service(
        "case_management.case_service",
        "CaseService",
        args.root,
    )
    status = None if args.status == "all" else args.status
    return service.list_cases(status=status)


def _handle_case_show(args: argparse.Namespace) -> Any:
    service = _load_service(
        "case_management.case_service",
        "CaseService",
        args.root,
    )
    return service.open_case(args.case_id)


def _handle_case_close(args: argparse.Namespace) -> Any:
    service = _load_service(
        "case_management.case_service",
        "CaseService",
        args.root,
    )
    return service.close_case(
        case_id=args.case_id,
        conclusion=args.conclusion,
    )


def _handle_collect(args: argparse.Namespace) -> Any:
    service = _load_service(
        "collection.collection_service",
        "CollectionService",
        args.root,
    )
    return service.collect_case(
        case_id=args.case_id,
        mode=args.mode,
        agent_id=args.agent_id,
    )


def _handle_preserve(args: argparse.Namespace) -> Any:
    service = _load_service(
        "evidence.evidence_service",
        "EvidenceService",
        args.root,
    )
    if args.rebuild:
        return service.preserve_case(args.case_id, rebuild=True)
    return service.ensure_preserved(args.case_id)


def _handle_verify(args: argparse.Namespace) -> Any:
    service = _load_service(
        "evidence.evidence_service",
        "EvidenceService",
        args.root,
    )
    return service.verify_case(args.case_id)


def _handle_process(args: argparse.Namespace) -> Any:
    service = _load_service(
        "integrations.integration_service",
        "IntegrationService",
        args.root,
    )
    return service.process_case(
        args.case_id,
        tool_ids=tuple(args.tools) if args.tools else None,
        continue_on_error=not args.stop_on_error,
    )


def _handle_analyze(args: argparse.Namespace) -> Any:
    service = _load_service(
        "analysis.analysis_service",
        "AnalysisService",
        args.root,
    )
    return service.analyze(case_id=args.case_id)


def _handle_report(args: argparse.Namespace) -> Any:
    service = _load_service(
        "reporting.report_service",
        "ReportService",
        args.root,
    )
    formats = tuple(args.formats or ("html", "json"))
    return service.generate(args.case_id, formats=formats)


def main(argv: Sequence[str] | None = None) -> int:
    from common.lab_env import load_lab_env

    load_lab_env()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], Any] = args.handler

    try:
        _print_result(handler(args))
        return EXIT_OK
    except KeyboardInterrupt:
        print("\nĐã hủy thao tác.", file=sys.stderr)
        return 130
    except (CliDependencyError, FileNotFoundError, ValueError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # pragma: no cover - last-resort entry-point guard
        print(f"Thao tác thất bại: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
