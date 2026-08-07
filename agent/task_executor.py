"""Execute allowlisted collectors and build a hashed Agent bundle."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from case_management.case_paths import RAW_ARTIFACT_DIRECTORIES
from clients.local_client import LocalClient
from collection.collector_registry import (
    CollectorOutput,
    CollectorRegistry,
    build_default_registry,
)
from common.enums import (
    ArtifactType,
    CollectionStatus,
    EvidenceCategory,
    OperationMode,
)
from common.exceptions import AgentError
from common.json_utils import write_json
from common.time_utils import utc_now, utc_now_iso
from evidence.hash_calculator import HashCalculator
from models.collection_plan import CollectionPlan
from models.collection_result import CollectionResult
from models.evidence_item import EvidenceItem, stable_evidence_id
from models.evidence_manifest import EvidenceManifest
from agent.agent_logger import AgentLogger
from agent.configuration import AgentSettings
from agent.local_buffer import AgentTask, LocalBuffer


class TaskExecutor:
    def __init__(
        self,
        settings: AgentSettings,
        buffer: LocalBuffer,
        logger: AgentLogger,
        *,
        registry: CollectorRegistry | None = None,
        local_client: LocalClient | None = None,
    ) -> None:
        self.settings = settings
        self.buffer = buffer
        self.logger = logger
        self.registry = registry or build_default_registry()
        self.local_client = local_client or LocalClient(
            timeout_seconds=settings.command_timeout_seconds
        )
        self._pool = ThreadPoolExecutor(
            max_workers=settings.max_concurrent_tasks,
            thread_name_prefix="forensic-agent",
        )
        self._futures: dict[str, Future[None]] = {}
        self._lock = threading.RLock()
        unknown = set(settings.collector_allowlist) - set(
            self.registry.ids()
        )
        if unknown:
            raise AgentError(
                f"Collector allowlist chưa được triển khai: {sorted(unknown)}"
            )

    def submit(
        self,
        plan: CollectionPlan | dict[str, Any],
        *,
        background: bool = True,
    ) -> AgentTask:
        normalized_plan = (
            plan
            if isinstance(plan, CollectionPlan)
            else self._parse_plan(plan)
        )
        self._validate_plan(normalized_plan)
        with self._lock:
            active_count = sum(
                task.status in {"queued", "running"}
                for task in self.buffer.list()
            )
            if active_count >= self.settings.max_concurrent_tasks:
                raise AgentError(
                    "Agent đã đạt giới hạn task đang chạy."
                )
            task = self.buffer.create(normalized_plan.to_dict())
            self.logger.log(
                "task_submitted",
                details={
                    "task_id": task.task_id,
                    "case_id": normalized_plan.case_id,
                    "plan_id": normalized_plan.plan_id,
                    "collectors": list(
                        self._collector_ids(normalized_plan)
                    ),
                },
            )
            if background:
                self._futures[task.task_id] = self._pool.submit(
                    self._execute,
                    task.task_id,
                    normalized_plan,
                )
                return task
        self._execute(task.task_id, normalized_plan)
        return self.buffer.get(task.task_id)

    def wait(
        self,
        task_id: str,
        *,
        timeout: float | None = None,
    ) -> AgentTask:
        with self._lock:
            future = self._futures.get(task_id)
        if future is not None:
            future.result(timeout=timeout)
        return self.buffer.get(task_id)

    def close(self, *, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait, cancel_futures=not wait)
        self.local_client.close()

    def _execute(
        self,
        task_id: str,
        plan: CollectionPlan,
    ) -> None:
        self.buffer.mark_running(task_id)
        self.logger.log(
            "task_started",
            details={"task_id": task_id, "case_id": plan.case_id},
        )
        try:
            workspace = self.buffer.workspace(task_id)
            results = self._run_collectors(plan, workspace)
            self._write_metadata(plan, results, workspace)
            bundle_path, digest, size = self._build_bundle(
                task_id,
                workspace,
            )
            self.buffer.mark_completed(
                task_id,
                collection_results=tuple(
                    result.to_dict() for result in results
                ),
                bundle_path=bundle_path,
                bundle_sha256=digest,
                bundle_size_bytes=size,
            )
            self.logger.log(
                "task_completed",
                details={
                    "task_id": task_id,
                    "collector_count": len(results),
                    "failed_count": sum(
                        not result.succeeded for result in results
                    ),
                    "bundle_sha256": digest,
                    "bundle_size_bytes": size,
                },
            )
        except Exception as exc:
            try:
                self.buffer.mark_failed(task_id, str(exc))
            finally:
                self.logger.log(
                    "task_failed",
                    status="failed",
                    details={
                        "task_id": task_id,
                        "error": _safe_error(exc),
                    },
                )

    def _run_collectors(
        self,
        plan: CollectionPlan,
        workspace: Path,
    ) -> tuple[CollectionResult, ...]:
        results: list[CollectionResult] = []
        for collector_id in self._collector_ids(plan):
            started_at = utc_now()
            collector = self.registry.get(collector_id)
            try:
                destination = self._destination(
                    workspace,
                    collector_id,
                    collector.category,
                )
                output = collector.collect(
                    self.local_client,
                    destination,
                    plan.options,
                )
                output_paths = self._persist_output(
                    collector_id,
                    collector.category,
                    collector.output_filename,
                    output,
                    workspace,
                    destination,
                )
                result = CollectionResult(
                    case_id=plan.case_id,
                    plan_id=plan.plan_id,
                    collector_id=collector_id,
                    status=(
                        CollectionStatus.PARTIAL
                        if output.warnings
                        else CollectionStatus.SUCCEEDED
                    ),
                    started_at=started_at,
                    finished_at=utc_now(),
                    record_count=output.record_count,
                    warnings=output.warnings,
                    metadata={
                        **output.metadata,
                        "mode": OperationMode.AGENT.value,
                        "category": collector.category.value,
                        "output_paths": output_paths,
                    },
                )
            except Exception as exc:
                result = CollectionResult(
                    case_id=plan.case_id,
                    plan_id=plan.plan_id,
                    collector_id=collector_id,
                    status=CollectionStatus.FAILED,
                    started_at=started_at,
                    finished_at=utc_now(),
                    errors=(_safe_error(exc),),
                    metadata={
                        "mode": OperationMode.AGENT.value,
                        "category": collector.category.value,
                    },
                )
            results.append(result)
        return tuple(results)

    def _persist_output(
        self,
        collector_id: str,
        category: EvidenceCategory,
        output_filename: str | None,
        output: CollectorOutput,
        workspace: Path,
        destination: Path,
    ) -> tuple[str, ...]:
        if category is EvidenceCategory.LIVE:
            filename = output_filename or f"{collector_id}.json"
            path = write_json(destination / filename, output.data)
            self._validate_output_file(path, destination)
            return (path.relative_to(workspace).as_posix(),)

        paths: list[str] = []
        for item in output.files:
            path = self._validate_output_file(item, destination)
            paths.append(path.relative_to(workspace).as_posix())
        return tuple(paths)

    def _validate_output_file(
        self,
        value: str | Path,
        destination: Path,
    ) -> Path:
        candidate = Path(value).expanduser()
        if candidate.is_symlink():
            raise AgentError(
                "Collector output không được là symbolic link."
            )
        path = candidate.resolve()
        try:
            path.relative_to(destination.resolve())
        except ValueError as exc:
            raise AgentError(
                "Collector trả về output ngoài destination."
            ) from exc
        if not path.is_file():
            raise AgentError("Collector output không tồn tại.")
        if path.stat().st_size > self.settings.max_file_size_bytes:
            raise AgentError(
                f"Collector output vượt giới hạn kích thước: {path.name}"
            )
        return path

    def _write_metadata(
        self,
        plan: CollectionPlan,
        results: tuple[CollectionResult, ...],
        workspace: Path,
    ) -> None:
        write_json(workspace / "collection_plan.json", plan.to_dict())
        acquisition = workspace / "acquisition"
        acquisition.mkdir(parents=True, exist_ok=True)
        evidence_files = tuple(
            sorted(
                (
                    path
                    for path in acquisition.rglob("*")
                    if path.is_file() and not path.is_symlink()
                ),
                key=lambda item: item.as_posix().casefold(),
            )
        )
        calculator = HashCalculator()
        contexts: dict[
            str,
            tuple[CollectionResult, EvidenceCategory, ArtifactType],
        ] = {}
        for collection_result in results:
            raw_category = collection_result.metadata.get("category")
            raw_paths = collection_result.metadata.get("output_paths", ())
            if not isinstance(raw_paths, (list, tuple)):
                continue
            try:
                category = EvidenceCategory(str(raw_category))
                artifact_type = ArtifactType(collection_result.collector_id)
            except ValueError:
                continue
            for stored_path in raw_paths:
                if isinstance(stored_path, str):
                    contexts[stored_path] = (
                        collection_result,
                        category,
                        artifact_type,
                    )

        hostname = socket.gethostname().strip() or self.settings.agent_id
        generated_at = utc_now()
        items: list[EvidenceItem] = []
        hash_lines: list[str] = []
        evidence_ids: dict[str, list[str]] = {}
        for path in evidence_files:
            hash_result = calculator.calculate(path)
            stored_path = path.relative_to(workspace).as_posix()
            context = contexts.get(stored_path)
            if context is None:
                raise AgentError(
                    "Không xác định được collector sở hữu evidence: "
                    f"{stored_path}"
                )
            collection_result, category, artifact_type = context
            evidence_id = stable_evidence_id(
                plan.case_id,
                stored_path,
                hash_result.sha256,
            )
            item = EvidenceItem(
                case_id=plan.case_id,
                evidence_id=evidence_id,
                artifact_type=artifact_type,
                category=category,
                source_path=stored_path,
                stored_path=stored_path,
                collector_id=collection_result.collector_id,
                hostname=hostname,
                sha256=hash_result.sha256,
                size_bytes=hash_result.size_bytes,
                collected_at=(
                    collection_result.finished_at or generated_at
                ),
                metadata={
                    "collected_by": self.settings.agent_id,
                    "mode": OperationMode.AGENT.value,
                    "source_path_inferred": True,
                },
            )
            items.append(item)
            evidence_ids.setdefault(
                collection_result.collector_id,
                [],
            ).append(evidence_id)
            hash_lines.append(f"{hash_result.sha256}  {stored_path}")

        for collection_result in results:
            collection_result.evidence_item_ids = tuple(
                evidence_ids.get(collection_result.collector_id, ())
            )
        write_json(
            workspace / "collection_results.json",
            {
                "schema_version": 1,
                "case_id": plan.case_id,
                "plan_id": plan.plan_id,
                "result_count": len(results),
                "collection_results": [
                    result.to_dict() for result in results
                ],
            },
        )

        manifest = EvidenceManifest(
            case_id=plan.case_id,
            generated_by=self.settings.agent_id,
            generated_at=generated_at,
            evidence_items=tuple(items),
        )
        write_json(
            acquisition / "manifest.json",
            manifest.to_dict(),
        )
        _atomic_write_text(
            acquisition / "hashes.sha256",
            "\n".join(hash_lines) + ("\n" if hash_lines else ""),
        )
        write_json(
            acquisition / "chain_of_custody.json",
            {
                "schema_version": 1,
                "case_id": plan.case_id,
                "entries": [
                    {
                        "action": "evidence_registered",
                        "actor": self.settings.agent_id,
                        "timestamp": utc_now_iso(),
                        "evidence_id": item.evidence_id,
                        "stored_path": item.stored_path,
                        "sha256": item.sha256,
                        "size_bytes": item.size_bytes,
                        "collector_id": item.collector_id,
                        "hostname": item.hostname,
                    }
                    for item in items
                ],
                "updated_at": utc_now_iso(),
            },
        )

    def _build_bundle(
        self,
        task_id: str,
        workspace: Path,
    ) -> tuple[Path, str, int]:
        bundle = self.buffer.task_directory(task_id) / "evidence_bundle.zip"
        temporary = bundle.with_name(f".{bundle.name}.part")
        temporary.unlink(missing_ok=True)
        files = tuple(
            sorted(
                (
                    path
                    for path in workspace.rglob("*")
                    if path.is_file()
                ),
                key=lambda item: item.as_posix().casefold(),
            )
        )
        try:
            with zipfile.ZipFile(
                temporary,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
                allowZip64=True,
            ) as archive:
                for path in files:
                    if path.is_symlink():
                        raise AgentError(
                            "Bundle không chấp nhận symbolic link."
                        )
                    archive.write(
                        path,
                        arcname=path.relative_to(workspace).as_posix(),
                    )
            size = temporary.stat().st_size
            if size > self.settings.max_bundle_size_bytes:
                raise AgentError(
                    "Evidence Bundle vượt giới hạn kích thước."
                )
            os.replace(temporary, bundle)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        hash_result = HashCalculator().calculate(bundle)
        return bundle, hash_result.sha256, hash_result.size_bytes

    def _validate_plan(self, plan: CollectionPlan) -> None:
        if plan.mode is not OperationMode.AGENT:
            raise AgentError("Agent chỉ nhận Collection Plan ở Agent Mode.")
        if plan.target_agent_id != self.settings.agent_id:
            raise AgentError(
                "Collection Plan không dành cho Agent này."
            )
        requested = set(self._collector_ids(plan))
        blocked = requested - set(self.settings.collector_allowlist)
        if blocked:
            raise AgentError(
                f"Collector không nằm trong allowlist: {sorted(blocked)}"
            )

    @staticmethod
    def _parse_plan(data: dict[str, Any]) -> CollectionPlan:
        if not isinstance(data, dict):
            raise TypeError("collection_plan phải là object.")
        try:
            return CollectionPlan.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(
                f"Collection Plan không hợp lệ: {exc}"
            ) from exc

    @staticmethod
    def _collector_ids(
        plan: CollectionPlan,
    ) -> tuple[str, ...]:
        return (*plan.live_collectors, *plan.artifact_collectors)

    @staticmethod
    def _destination(
        workspace: Path,
        collector_id: str,
        category: EvidenceCategory,
    ) -> Path:
        if category is EvidenceCategory.LIVE:
            destination = workspace / "acquisition" / "live"
        else:
            try:
                directory_name = RAW_ARTIFACT_DIRECTORIES[collector_id]
            except KeyError as exc:
                raise AgentError(
                    f"Không có raw directory cho {collector_id}."
                ) from exc
            destination = (
                workspace
                / "acquisition"
                / "raw"
                / directory_name
            )
        destination.mkdir(parents=True, exist_ok=True)
        return destination


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _safe_error(exc: Exception, limit: int = 1000) -> str:
    text = " ".join(str(exc).split()) or exc.__class__.__name__
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."
