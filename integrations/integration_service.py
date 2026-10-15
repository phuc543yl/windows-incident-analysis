"""Orchestrate DFIR tools, output parsers, and the processing pipeline."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from common.enums import ArtifactType, ToolRunStatus
from common.exceptions import ToolIntegrationError, ToolkitError
from evidence.integrity_verifier import IntegrityVerifier
from integrations.adapters import BaseAdapter, create_adapter
from integrations.tool_registry import ToolDefinition, ToolRegistry
from integrations.tool_runner import ToolRunner
from models.normalized_record import NormalizedRecord
from models.tool_result import ToolResult
from processing.live_record_loader import LiveRecordLoader
from processing.processing_pipeline import ProcessingPipeline

AdapterFactory = Callable[[ToolDefinition, ToolRunner], BaseAdapter]


@dataclass(frozen=True, slots=True)
class IntegrationResult:
    """Compact result of one tool-to-processing workflow."""

    case_id: str
    requested_tools: tuple[str, ...]
    succeeded_tools: tuple[str, ...]
    skipped_tools: tuple[str, ...]
    failed_tools: tuple[str, ...]
    parsed_record_count: int
    normalized_count: int
    duplicate_count: int
    timeline_count: int
    records_path: Path | None
    timeline_path: Path | None
    tool_results: tuple[ToolResult, ...]
    warnings: tuple[str, ...] = ()
    live_record_count: int = 0


class IntegrationService:
    """Run configured tools for a Case and persist normalized output."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        registry: ToolRegistry | None = None,
        runner: ToolRunner | None = None,
        pipeline: ProcessingPipeline | None = None,
        adapter_factory: AdapterFactory = create_adapter,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.registry = registry or ToolRegistry(self.repository.project)
        self.runner = runner or ToolRunner(
            self.repository.project,
            registry=self.registry,
        )
        self.pipeline = pipeline or ProcessingPipeline(
            self.repository.project,
            actor=actor,
        )
        self.adapter_factory = adapter_factory
        self.actor = actor.strip() or "analyst"

    def process_case(
        self,
        case_id: str,
        *,
        tool_ids: Iterable[str] | None = None,
        verify_integrity: bool = True,
        continue_on_error: bool = True,
        on_progress: Callable[[str], None] | None = None,
    ) -> IntegrationResult:
        """Execute selected tools, parse their output, then normalize it."""

        report = on_progress or (lambda _message: None)
        report("Đang kiểm tra Case và danh sách công cụ...")
        case = self.repository.require_open(case_id)
        paths = self.repository.paths(case.case_id)
        target = self.repository.load_target(case.case_id)
        requested = self._requested_tools(case.case_id, tool_ids)

        if verify_integrity:
            report("Đang kiểm tra tính toàn vẹn bằng chứng...")
            IntegrityVerifier(
                case.case_id,
                self.repository.project,
            ).verify()

        records: list[NormalizedRecord] = []
        results: list[ToolResult] = []
        succeeded: list[str] = []
        skipped: list[str] = []
        failed: list[str] = []
        warnings: list[str] = []

        report("Đang đọc dữ liệu live đã thu thập...")
        try:
            live_records = LiveRecordLoader(self.repository.project).load(case.case_id)
            records.extend(live_records)
            report(f"Đã đọc {len(live_records)} bản ghi live.")
        except (ToolkitError, OSError, TypeError, ValueError) as exc:
            live_records = ()
            warnings.append(f"live data: {exc}")
            report(f"Cảnh báo: {warnings[-1]}")
            if not continue_on_error:
                raise ToolIntegrationError(warnings[-1]) from exc

        for index, tool_id in enumerate(requested, start=1):
            report(f"Công cụ {index}/{len(requested)}: {tool_id}...")
            try:
                definition = self.registry.get(
                    tool_id,
                    require_enabled=True,
                )
                adapter = self.adapter_factory(definition, self.runner)
                inputs = self._input_paths(
                    paths.raw_artifact_dir(adapter.artifact_type.value),
                    adapter.artifact_type,
                )
                if not inputs:
                    skipped.append(tool_id)
                    warnings.append(
                        f"{tool_id}: chưa có artifact {adapter.artifact_type.value}."
                    )
                    report(f"Bỏ qua: {warnings[-1]}")
                    continue

                result = adapter.run(
                    case_id=case.case_id,
                    input_paths=inputs,
                    verify_integrity=False,
                )
                results.append(result)
                if result.status is not ToolRunStatus.SUCCEEDED:
                    failed.append(tool_id)
                    warnings.append(
                        f"{tool_id}: {result.error_message or result.status.value}"
                    )
                    report(f"Thất bại: {warnings[-1]}")
                    if not continue_on_error:
                        raise ToolIntegrationError(warnings[-1])
                    continue

                report(f"{tool_id}: đang đọc kết quả công cụ...")
                parsed = adapter.parse(
                    result,
                    hostname=target.hostname,
                )
                records.extend(parsed)
                succeeded.append(tool_id)
                report(f"{tool_id}: hoàn tất, {len(parsed)} bản ghi.")
            except (ToolkitError, OSError, TypeError, ValueError) as exc:
                if tool_id not in failed:
                    failed.append(tool_id)
                warnings.append(f"{tool_id}: {exc}")
                report(f"Thất bại: {warnings[-1]}")
                if not continue_on_error:
                    raise

        if not records:
            detail = "; ".join(warnings) or "không có tool nào tạo output"
            AuditLogger(case.case_id, self.repository.project).log(
                "integration_processing_failed",
                actor=self.actor,
                status="failed",
                details={"reason": detail},
            )
            raise ToolIntegrationError(
                "Không có bản ghi nào được parse; dữ liệu normalized cũ "
                f"không bị ghi đè. Chi tiết: {detail}"
            )

        report(f"Đang chuẩn hóa {len(records)} bản ghi...")
        processing = self.pipeline.process(
            case_id=case.case_id,
            records=records,
            **({"on_progress": on_progress} if on_progress is not None else {}),
        )
        result = IntegrationResult(
            case_id=case.case_id,
            requested_tools=requested,
            succeeded_tools=tuple(succeeded),
            skipped_tools=tuple(skipped),
            failed_tools=tuple(failed),
            parsed_record_count=len(records),
            normalized_count=processing.normalized_count,
            duplicate_count=processing.duplicate_count,
            timeline_count=processing.timeline_count,
            records_path=processing.records_path,
            timeline_path=processing.timeline_path,
            tool_results=tuple(results),
            warnings=tuple(warnings),
            live_record_count=len(live_records),
        )
        AuditLogger(case.case_id, self.repository.project).log(
            "integration_processing_completed",
            actor=self.actor,
            details={
                "requested_tools": list(result.requested_tools),
                "succeeded_tools": list(result.succeeded_tools),
                "skipped_tools": list(result.skipped_tools),
                "failed_tools": list(result.failed_tools),
                "parsed_record_count": result.parsed_record_count,
                "live_record_count": result.live_record_count,
                "normalized_count": result.normalized_count,
            },
        )
        report(
            f"Xử lý hoàn tất: {result.normalized_count} bản ghi, "
            f"{result.timeline_count} sự kiện dòng thời gian, "
            f"{len(result.warnings)} cảnh báo."
        )
        return result

    def _requested_tools(
        self,
        case_id: str,
        tool_ids: Iterable[str] | None,
    ) -> tuple[str, ...]:
        if tool_ids is None:
            plan = self.repository.load_collection_plan(case_id)
            values = plan.options.get("tools", ())
        else:
            values = tool_ids
        if isinstance(values, str):
            values = (values,)
        try:
            candidates = tuple(values)
        except TypeError as exc:
            raise ToolIntegrationError(
                "Danh sách tool trong Collection Plan không hợp lệ."
            ) from exc

        result: list[str] = []
        for value in candidates:
            normalized = str(value).strip().lower()
            if not normalized:
                raise ToolIntegrationError("Tool ID không được để trống.")
            if normalized not in result:
                result.append(normalized)
        if not result:
            raise ToolIntegrationError("Case không có tool nào được chọn để xử lý.")
        return tuple(result)

    @staticmethod
    def _input_paths(
        directory: Path,
        artifact_type: ArtifactType,
    ) -> tuple[Path, ...]:
        if not directory.is_dir():
            return ()
        files: list[Path] = []
        for path in sorted(
            directory.rglob("*"),
            key=lambda item: item.as_posix().casefold(),
        ):
            if path.is_symlink():
                raise ToolIntegrationError(
                    f"Artifact không được là symbolic link: {path}"
                )
            if path.is_file():
                files.append(path)
        if not files:
            return ()

        if artifact_type is ArtifactType.AMCACHE:
            return _select_named_file(
                files,
                names=("amcache.hve",),
                description="Amcache.hve",
            )
        if artifact_type is ArtifactType.MFT:
            return _select_named_file(
                files,
                names=("$mft", "mft"),
                description="$MFT",
            )
        return (directory,)


def _select_named_file(
    files: list[Path],
    *,
    names: tuple[str, ...],
    description: str,
) -> tuple[Path, ...]:
    accepted = {name.casefold() for name in names}
    matches = [path for path in files if path.name.casefold() in accepted]
    if not matches:
        raise ToolIntegrationError(
            f"Không tìm thấy file {description} trong artifact directory."
        )
    if len(matches) > 1:
        raise ToolIntegrationError(
            f"Tìm thấy nhiều file {description}; không thể tự chọn."
        )
    return (matches[0],)
