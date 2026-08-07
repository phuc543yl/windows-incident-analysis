"""Orchestrate Local and Agent collection for one Case."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from case_management.audit_logger import AuditLogger
from case_management.case_repository import CaseRepository
from clients.agent_client import AgentClient
from clients.local_client import LocalClient
from collection.agent_bundle_importer import AgentBundleImporter
from collection.collector_registry import (
    CollectorOutput,
    CollectorRegistry,
    build_default_registry,
)
from collection.plan_builder import PlanBuilder
from common.enums import CollectionStatus, EvidenceCategory, OperationMode
from common.exceptions import CollectionError
from common.json_utils import append_jsonl, write_json
from common.time_utils import utc_now
from models.collection_plan import CollectionPlan
from models.collection_result import CollectionResult


class CollectionService:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        registry: CollectorRegistry | None = None,
        local_client: LocalClient | None = None,
        agent_client: AgentClient | None = None,
        continue_on_error: bool = True,
    ) -> None:
        self.repository = CaseRepository(root)
        self.registry = registry or build_default_registry()
        self.local_client = local_client
        self.agent_client = agent_client
        self.continue_on_error = bool(continue_on_error)

    def collect_case(
        self,
        case_id: str,
        mode: OperationMode | str | None = None,
        agent_id: str | None = None,
    ) -> list[CollectionResult]:
        case = self.repository.require_open(case_id)
        plan = self.repository.load_collection_plan(case.case_id)
        if (
            agent_id is not None
            and mode is None
            and plan.mode is OperationMode.LOCAL
        ):
            raise ValueError(
                "agent_id chỉ được dùng khi mode là 'agent'."
            )
        plan = PlanBuilder.with_overrides(
            plan,
            mode=mode,
            target_agent_id=agent_id,
        )
        if plan.mode is OperationMode.AGENT:
            return self._collect_agent(plan)
        return self._collect_local(plan)

    def close(self) -> None:
        if self.local_client is not None:
            self.local_client.close()
        if self.agent_client is not None:
            self.agent_client.close()

    def _collect_local(
        self,
        plan: CollectionPlan,
    ) -> list[CollectionResult]:
        client = self.local_client or LocalClient()
        paths = self.repository.paths(plan.case_id)
        options = dict(plan.options)
        results: list[CollectionResult] = []
        collector_ids = (
            *plan.live_collectors,
            *plan.artifact_collectors,
        )
        audit = AuditLogger(plan.case_id, self.repository.project)
        audit.log(
            "collection_started",
            details={
                "plan_id": plan.plan_id,
                "mode": plan.mode.value,
                "collectors": list(collector_ids),
            },
        )

        for collector_id in collector_ids:
            started_at = utc_now()
            collector = None
            try:
                collector = self.registry.get(collector_id)
                destination = (
                    paths.live
                    if collector.category is EvidenceCategory.LIVE
                    else paths.raw_artifact_dir(collector_id)
                )
                output = collector.collect(client, destination, options)
                output_paths = self._persist_output(
                    collector_id,
                    collector.category,
                    collector.output_filename,
                    output,
                    paths.root,
                    destination,
                )
                status = (
                    CollectionStatus.PARTIAL
                    if output.warnings
                    else CollectionStatus.SUCCEEDED
                )
                result = CollectionResult(
                    case_id=plan.case_id,
                    plan_id=plan.plan_id,
                    collector_id=collector_id,
                    status=status,
                    started_at=started_at,
                    finished_at=utc_now(),
                    record_count=output.record_count,
                    warnings=output.warnings,
                    metadata={
                        **output.metadata,
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
                        "category": (
                            collector.category.value
                            if collector is not None
                            else "unknown"
                        )
                    },
                )
                self._record_result(result)
                results.append(result)
                if not self.continue_on_error:
                    audit.log(
                        "collection_failed",
                        status="failed",
                        details={
                            "plan_id": plan.plan_id,
                            "collector_id": collector_id,
                            "error": _safe_error(exc),
                        },
                    )
                    raise CollectionError(
                        f"Collector {collector_id} thất bại: "
                        f"{_safe_error(exc)}"
                    ) from exc
                continue

            self._record_result(result)
            results.append(result)

        audit.log(
            "collection_completed",
            status=(
                "partial"
                if any(not result.succeeded for result in results)
                else "success"
            ),
            details={
                "plan_id": plan.plan_id,
                "succeeded": sum(
                    result.succeeded for result in results
                ),
                "failed": sum(
                    not result.succeeded for result in results
                ),
            },
        )
        return results

    def _collect_agent(
        self,
        plan: CollectionPlan,
    ) -> list[CollectionResult]:
        client = self.agent_client
        if client is None:
            config_path = self.repository.project / "config" / "agent.json"
            client = AgentClient.from_config(config_path)
            self.agent_client = client

        audit = AuditLogger(plan.case_id, self.repository.project)
        audit.log(
            "agent_collection_started",
            details={
                "plan_id": plan.plan_id,
                "agent_id": plan.target_agent_id,
            },
        )
        try:
            task_id = client.submit_collection(plan)
            task = client.wait_for_task(task_id)
            paths = self.repository.paths(plan.case_id)
            safe_task_id = re.sub(r"[^A-Za-z0-9_.-]", "_", task_id)
            bundle_path = paths.bundles / f"{safe_task_id}.zip"
            client.download_bundle(
                task_id,
                bundle_path,
                expected_sha256=task.get("bundle_sha256"),
            )
            import_result = AgentBundleImporter(
                self.repository.project,
                actor="collection-service",
            ).import_bundle(
                plan.case_id,
                bundle_path,
                expected_sha256=task.get("bundle_sha256"),
                task_id=task_id,
                agent_id=plan.target_agent_id or "agent",
            )
            results = self._agent_results(plan, task, bundle_path)
            for result in results:
                result.metadata["bundle_imported"] = True
                result.metadata["imported_evidence_count"] = (
                    import_result.item_count
                )
        except Exception as exc:
            audit.log(
                "agent_collection_failed",
                status="failed",
                details={
                    "plan_id": plan.plan_id,
                    "error": _safe_error(exc),
                },
            )
            if isinstance(exc, CollectionError):
                raise
            raise CollectionError(
                f"Agent collection thất bại: {_safe_error(exc)}"
            ) from exc

        for result in results:
            self._record_result(result)
        audit.log(
            "agent_collection_completed",
            status=(
                "partial"
                if any(not result.succeeded for result in results)
                else "success"
            ),
            details={
                "plan_id": plan.plan_id,
                "task_id": task_id,
                "bundle_path": bundle_path.relative_to(
                    paths.root
                ).as_posix(),
                "bundle_imported": True,
                "imported_evidence_count": import_result.item_count,
            },
        )
        return results

    def _agent_results(
        self,
        plan: CollectionPlan,
        task: dict[str, Any],
        bundle_path: Path,
    ) -> list[CollectionResult]:
        case_root = self.repository.paths(plan.case_id).root
        bundle_reference = bundle_path.relative_to(case_root).as_posix()
        raw_results = task.get("collection_results")
        if isinstance(raw_results, list) and raw_results:
            results = [
                CollectionResult.from_dict(dict(item))
                for item in raw_results
                if isinstance(item, dict)
            ]
            if not results:
                raise CollectionError(
                    "Agent không trả về CollectionResult hợp lệ."
                )
            for result in results:
                if (
                    result.case_id != plan.case_id
                    or result.plan_id != plan.plan_id
                ):
                    raise CollectionError(
                        "CollectionResult từ Agent không khớp Case/Plan."
                    )
                result.metadata["bundle_path"] = bundle_reference
            return results

        now = utc_now()
        return [
            CollectionResult(
                case_id=plan.case_id,
                plan_id=plan.plan_id,
                collector_id=collector_id,
                status=CollectionStatus.SUCCEEDED,
                started_at=now,
                finished_at=now,
                metadata={
                    "mode": OperationMode.AGENT.value,
                    "task_id": task.get("task_id", ""),
                    "bundle_path": bundle_reference,
                },
            )
            for collector_id in (
                *plan.live_collectors,
                *plan.artifact_collectors,
            )
        ]

    def _persist_output(
        self,
        collector_id: str,
        category: EvidenceCategory,
        output_filename: str | None,
        output: CollectorOutput,
        case_root: Path,
        destination: Path,
    ) -> list[str]:
        if category is EvidenceCategory.LIVE:
            filename = output_filename or f"{collector_id}.json"
            output_path = write_json(destination / filename, output.data)
            return [output_path.relative_to(case_root).as_posix()]

        output_paths: list[str] = []
        destination_root = destination.resolve()
        for path in output.files:
            resolved = path.resolve()
            try:
                resolved.relative_to(destination_root)
            except ValueError as exc:
                raise CollectionError(
                    f"Collector {collector_id} trả về file ngoài thư mục raw."
                ) from exc
            if not resolved.is_file():
                raise CollectionError(
                    f"Collector {collector_id} trả về file không tồn tại: "
                    f"{resolved}"
                )
            output_paths.append(resolved.relative_to(case_root).as_posix())
        return output_paths

    def _record_result(self, result: CollectionResult) -> None:
        paths = self.repository.paths(result.case_id)
        append_jsonl(paths.collection_log, result.to_dict())


def _safe_error(exc: Exception, limit: int = 1000) -> str:
    text = " ".join(str(exc).split()) or exc.__class__.__name__
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."
