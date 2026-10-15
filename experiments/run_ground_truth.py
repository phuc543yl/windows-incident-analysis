"""CLI entry point for the four synthetic ground-truth experiments."""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.ground_truth import (
    run_ground_truth_suite,
    write_ground_truth_results,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Chạy bộ thực nghiệm ground truth tổng hợp của Crow-Eye."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Thư mục gốc Crow-Eye.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Thư mục lưu JSON/CSV kết quả.",
    )
    arguments = parser.parse_args(argv)
    root = arguments.root.expanduser().resolve()
    output = (
        arguments.output.expanduser().resolve()
        if arguments.output is not None
        else root / "runtime" / "experiments"
    )
    result = run_ground_truth_suite(root)
    print(
        "P/R/F1 được tính theo rule trên mỗi scenario tổng hợp; không phải độ chính xác trên evidence VM thật."
    )
    json_path, csv_path = write_ground_truth_results(result, output)

    for item in result.results:
        status = "PASS" if item.passed else "FAIL"
        print(
            f"{status:4} | {item.scenario_id:28} | "
            f"alerts={item.actual_alert_count}/{item.expected_alert_count} | "
            f"P={item.precision:.2f} R={item.recall:.2f} F1={item.f1_score:.2f} | "
            f"time={item.total_seconds:.4f}s | "
            f"case={item.case_size_bytes / 1024:.2f} KiB"
        )
    print(
        f"TOTAL | {result.passed_count}/{result.scenario_count} passed | "
        f"P={result.precision:.2f} R={result.recall:.2f} "
        f"F1={result.f1_score:.2f} | "
        f"mean_time={result.mean_total_seconds:.4f}s | "
        f"mean_case={result.mean_case_size_bytes / 1024:.2f} KiB"
    )
    print(f"JSON: {json_path}")
    print(f"CSV : {csv_path}")
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
