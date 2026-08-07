"""Run synthetic incident scenarios against declared ground truth."""

from __future__ import annotations

import csv
import json
import shutil
import tempfile
from time import perf_counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from analysis.analysis_service import AnalysisService
from case_management.case_service import CaseService
from common.json_utils import read_json_object, write_json
from common.paths import project_root
from models.alert import Alert
from processing.processing_pipeline import ProcessingPipeline


@dataclass(frozen=True, slots=True)
class GroundTruthResult:
    scenario_id: str
    title: str
    input_record_count: int
    expected_alert_count: int
    actual_alert_count: int
    expected_rule_ids: tuple[str, ...]
    actual_rule_ids: tuple[str, ...]
    true_positive_rules: tuple[str, ...]
    false_positive_rules: tuple[str, ...]
    false_negative_rules: tuple[str, ...]
    expected_mitre_techniques: tuple[str, ...]
    detected_mitre_techniques: tuple[str, ...]
    missing_mitre_techniques: tuple[str, ...]
    precision: float
    recall: float
    f1_score: float
    input_size_bytes: int
    normalized_size_bytes: int
    timeline_size_bytes: int
    analysis_result_size_bytes: int
    case_size_bytes: int
    processing_seconds: float
    analysis_seconds: float
    total_seconds: float
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GroundTruthSuiteResult:
    scenario_count: int
    passed_count: int
    failed_count: int
    true_positive_rules: int
    false_positive_rules: int
    false_negative_rules: int
    precision: float
    recall: float
    f1_score: float
    total_input_size_bytes: int
    total_case_size_bytes: int
    mean_case_size_bytes: float
    mean_processing_seconds: float
    mean_analysis_seconds: float
    mean_total_seconds: float
    results: tuple[GroundTruthResult, ...]

    @property
    def passed(self) -> bool:
        return self.failed_count == 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        return data


def evaluate_scenario(
    scenario: dict[str, Any],
    alerts: Iterable[Alert],
    *,
    normalized_size_bytes: int = 0,
    timeline_size_bytes: int = 0,
    analysis_result_size_bytes: int = 0,
    case_size_bytes: int = 0,
    processing_seconds: float = 0.0,
    analysis_seconds: float = 0.0,
) -> GroundTruthResult:
    """Compare detected rules and MITRE mappings with declared ground truth."""
    ground_truth = scenario.get("ground_truth")
    if not isinstance(ground_truth, dict):
        raise ValueError("Scenario phải có object ground_truth.")

    alert_items = tuple(alerts)
    expected_rules = _string_set(ground_truth.get("expected_rule_ids"))
    actual_rules = {alert.rule_id for alert in alert_items}
    true_positives = expected_rules & actual_rules
    false_positives = actual_rules - expected_rules
    false_negatives = expected_rules - actual_rules
    precision, recall, f1_score = _metrics(
        len(true_positives),
        len(false_positives),
        len(false_negatives),
    )

    expected_mitre = _string_set(
        ground_truth.get("expected_mitre_techniques")
    )
    detected_mitre = {
        technique
        for alert in alert_items
        for technique in alert.mitre_techniques
    }
    missing_mitre = expected_mitre - detected_mitre
    expected_alert_count = _non_negative_int(
        ground_truth.get("expected_alert_count"),
        "expected_alert_count",
    )
    records = scenario.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("Scenario phải có records không rỗng.")

    passed = (
        not false_positives
        and not false_negatives
        and not missing_mitre
        and len(alert_items) == expected_alert_count
    )
    return GroundTruthResult(
        scenario_id=_required_text(scenario.get("scenario_id"), "scenario_id"),
        title=_required_text(scenario.get("title"), "title"),
        input_record_count=len(records),
        expected_alert_count=expected_alert_count,
        actual_alert_count=len(alert_items),
        expected_rule_ids=tuple(sorted(expected_rules)),
        actual_rule_ids=tuple(sorted(actual_rules)),
        true_positive_rules=tuple(sorted(true_positives)),
        false_positive_rules=tuple(sorted(false_positives)),
        false_negative_rules=tuple(sorted(false_negatives)),
        expected_mitre_techniques=tuple(sorted(expected_mitre)),
        detected_mitre_techniques=tuple(sorted(detected_mitre)),
        missing_mitre_techniques=tuple(sorted(missing_mitre)),
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        input_size_bytes=_records_size(records),
        normalized_size_bytes=_validated_size(
            normalized_size_bytes,
            "normalized_size_bytes",
        ),
        timeline_size_bytes=_validated_size(
            timeline_size_bytes,
            "timeline_size_bytes",
        ),
        analysis_result_size_bytes=_validated_size(
            analysis_result_size_bytes,
            "analysis_result_size_bytes",
        ),
        case_size_bytes=_validated_size(case_size_bytes, "case_size_bytes"),
        processing_seconds=_validated_duration(
            processing_seconds,
            "processing_seconds",
        ),
        analysis_seconds=_validated_duration(
            analysis_seconds,
            "analysis_seconds",
        ),
        total_seconds=_validated_duration(
            processing_seconds + analysis_seconds,
            "total_seconds",
        ),
        passed=passed,
    )


def run_ground_truth_suite(
    root: str | Path | None = None,
    *,
    scenario_dir: str | Path | None = None,
) -> GroundTruthSuiteResult:
    """Run all ground-truth fixtures in isolated temporary Case repositories."""
    project = project_root(root)
    fixtures = (
        Path(scenario_dir).expanduser().resolve()
        if scenario_dir is not None
        else project / "tests" / "fixtures" / "ground_truth"
    )
    scenario_paths = tuple(sorted(fixtures.glob("*.json")))
    if not scenario_paths:
        raise ValueError(f"Không tìm thấy ground-truth scenario trong {fixtures}")

    results: list[GroundTruthResult] = []
    for path in scenario_paths:
        scenario = read_json_object(path)
        _validate_scenario(scenario, path)
        with tempfile.TemporaryDirectory(prefix="croweye-ground-truth-") as temp:
            lab_root = Path(temp)
            shutil.copytree(project / "config", lab_root / "config")
            case = CaseService(
                lab_root,
                actor="ground-truth-experiment",
            ).create_case(
                title=f"Ground truth: {scenario['title']}",
                target_hostname=scenario["target_hostname"],
                profile_id=scenario["profile_id"],
            )
            paths = CaseService(lab_root).repository.paths(case.case_id)
            processing_started = perf_counter()
            processing = ProcessingPipeline(
                lab_root,
                actor="ground-truth-experiment",
            ).process(
                case_id=case.case_id,
                records=scenario["records"],
            )
            processing_seconds = perf_counter() - processing_started
            if processing.normalized_count != len(scenario["records"]):
                raise ValueError(
                    f"{scenario['scenario_id']}: normalized record count không khớp."
                )
            analysis_started = perf_counter()
            analysis = AnalysisService(
                lab_root,
                actor="ground-truth-experiment",
            ).analyze(case_id=case.case_id)
            analysis_seconds = perf_counter() - analysis_started
            results.append(
                evaluate_scenario(
                    scenario,
                    analysis.alerts,
                    normalized_size_bytes=_path_size(paths.normalized),
                    timeline_size_bytes=_path_size(paths.timeline_json),
                    analysis_result_size_bytes=sum(
                        _path_size(item)
                        for item in (
                            paths.findings_json,
                            paths.alerts_json,
                            paths.incidents_json,
                        )
                    ),
                    case_size_bytes=_path_size(paths.root),
                    processing_seconds=processing_seconds,
                    analysis_seconds=analysis_seconds,
                )
            )
    return _suite_result(tuple(results))


def write_ground_truth_results(
    result: GroundTruthSuiteResult,
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """Write JSON and CSV summaries suitable for the experiment chapter."""
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = write_json(
        destination / "ground_truth_results.json",
        result.to_dict(),
    )
    csv_path = destination / "ground_truth_results.csv"
    fieldnames = (
        "scenario_id",
        "passed",
        "input_record_count",
        "expected_alert_count",
        "actual_alert_count",
        "true_positive_rules",
        "false_positive_rules",
        "false_negative_rules",
        "precision",
        "recall",
        "f1_score",
        "processing_seconds",
        "analysis_seconds",
        "total_seconds",
        "input_size_bytes",
        "normalized_size_bytes",
        "timeline_size_bytes",
        "analysis_result_size_bytes",
        "case_size_bytes",
    )
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in result.results:
            writer.writerow(
                {
                    "scenario_id": item.scenario_id,
                    "passed": item.passed,
                    "input_record_count": item.input_record_count,
                    "expected_alert_count": item.expected_alert_count,
                    "actual_alert_count": item.actual_alert_count,
                    "true_positive_rules": ";".join(item.true_positive_rules),
                    "false_positive_rules": ";".join(item.false_positive_rules),
                    "false_negative_rules": ";".join(item.false_negative_rules),
                    "precision": f"{item.precision:.4f}",
                    "recall": f"{item.recall:.4f}",
                    "f1_score": f"{item.f1_score:.4f}",
                    "processing_seconds": f"{item.processing_seconds:.6f}",
                    "analysis_seconds": f"{item.analysis_seconds:.6f}",
                    "total_seconds": f"{item.total_seconds:.6f}",
                    "input_size_bytes": item.input_size_bytes,
                    "normalized_size_bytes": item.normalized_size_bytes,
                    "timeline_size_bytes": item.timeline_size_bytes,
                    "analysis_result_size_bytes": item.analysis_result_size_bytes,
                    "case_size_bytes": item.case_size_bytes,
                }
            )
    return json_path, csv_path


def _suite_result(
    results: tuple[GroundTruthResult, ...],
) -> GroundTruthSuiteResult:
    true_positives = sum(len(item.true_positive_rules) for item in results)
    false_positives = sum(len(item.false_positive_rules) for item in results)
    false_negatives = sum(len(item.false_negative_rules) for item in results)
    precision, recall, f1_score = _metrics(
        true_positives,
        false_positives,
        false_negatives,
    )
    passed_count = sum(item.passed for item in results)
    scenario_count = len(results)
    return GroundTruthSuiteResult(
        scenario_count=scenario_count,
        passed_count=passed_count,
        failed_count=len(results) - passed_count,
        true_positive_rules=true_positives,
        false_positive_rules=false_positives,
        false_negative_rules=false_negatives,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
        total_input_size_bytes=sum(item.input_size_bytes for item in results),
        total_case_size_bytes=sum(item.case_size_bytes for item in results),
        mean_case_size_bytes=(
            sum(item.case_size_bytes for item in results) / scenario_count
            if scenario_count
            else 0.0
        ),
        mean_processing_seconds=(
            sum(item.processing_seconds for item in results) / scenario_count
            if scenario_count
            else 0.0
        ),
        mean_analysis_seconds=(
            sum(item.analysis_seconds for item in results) / scenario_count
            if scenario_count
            else 0.0
        ),
        mean_total_seconds=(
            sum(item.total_seconds for item in results) / scenario_count
            if scenario_count
            else 0.0
        ),
        results=results,
    )


def _metrics(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1_score = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return precision, recall, f1_score


def _validate_scenario(scenario: dict[str, Any], path: Path) -> None:
    if scenario.get("schema_version") != 1:
        raise ValueError(f"{path.name}: schema_version phải bằng 1.")
    for key in ("scenario_id", "title", "profile_id", "target_hostname"):
        _required_text(scenario.get(key), key)
    records = scenario.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"{path.name}: records phải là list không rỗng.")
    if not isinstance(scenario.get("ground_truth"), dict):
        raise ValueError(f"{path.name}: thiếu ground_truth.")


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("Ground truth rule/MITRE list phải là list không rỗng.")
    result = {str(item).strip() for item in value if str(item).strip()}
    if not result:
        raise ValueError("Ground truth rule/MITRE list không được rỗng.")
    return result


def _non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} phải là số nguyên không âm.")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} phải là số nguyên không âm.") from exc
    if result < 0:
        raise ValueError(f"{field_name} phải là số nguyên không âm.")
    return result


def _required_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} không được để trống.")
    return text


def _records_size(records: list[Any]) -> int:
    payload = json.dumps(
        records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return len(payload.encode("utf-8"))


def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    if not path.is_dir():
        return 0
    return sum(
        item.stat().st_size
        for item in path.rglob("*")
        if item.is_file() and not item.is_symlink()
    )


def _validated_size(value: int, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} phải là số nguyên không âm.")
    result = int(value)
    if result < 0:
        raise ValueError(f"{field_name} phải là số nguyên không âm.")
    return result


def _validated_duration(value: float, field_name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} phải là số không âm.")
    result = float(value)
    if result < 0:
        raise ValueError(f"{field_name} phải là số không âm.")
    return result
