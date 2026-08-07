"""Convert collected live-state JSON files into NormalizedRecord objects."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.enums import ArtifactType
from common.exceptions import JsonFileError, ProcessingError
from common.json_utils import read_json, read_json_object
from models.evidence_manifest import EvidenceManifest
from models.normalized_record import NormalizedRecord

_LIVE_ARTIFACTS = {
    "system": ArtifactType.SYSTEM,
    "users": ArtifactType.USERS,
    "processes": ArtifactType.PROCESSES,
    "network": ArtifactType.NETWORK,
    "services": ArtifactType.SERVICES,
    "startup": ArtifactType.STARTUP,
}
_LIVE_SOURCE_TYPES = {
    "system": "live_system",
    "users": "live_user",
    "processes": "live_process",
    "network": "live_network",
    "services": "live_service",
    "startup": "live_startup",
}


class LiveRecordLoader:
    """Load Case ``acquisition/live`` snapshots into the common schema."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.repository = CaseRepository(root)

    def load(self, case_id: str) -> tuple[NormalizedRecord, ...]:
        case = self.repository.load_case(case_id)
        paths = self.repository.paths(case.case_id)
        target = self.repository.load_target(case.case_id)
        collected_at = self._manifest_timestamps(case.case_id)
        records: list[NormalizedRecord] = []

        for path in sorted(
            paths.live.rglob("*.json"),
            key=lambda item: item.as_posix().casefold(),
        ):
            if path.is_symlink():
                raise ProcessingError(
                    f"Live data không được là symbolic link: {path}"
                )
            collector_id = path.stem.casefold()
            artifact_type = _LIVE_ARTIFACTS.get(collector_id)
            if artifact_type is None:
                continue
            try:
                value = read_json(path)
            except JsonFileError as exc:
                raise ProcessingError(str(exc)) from exc
            rows = self._rows(value, collector_id, path)
            raw_reference = path.relative_to(paths.root).as_posix()
            timestamp = collected_at.get(
                raw_reference,
                datetime.fromtimestamp(
                    path.stat().st_mtime,
                    tz=timezone.utc,
                ),
            )
            for index, row in enumerate(rows, start=1):
                records.append(
                    self._record(
                        case_id=case.case_id,
                        collector_id=collector_id,
                        artifact_type=artifact_type,
                        row=row,
                        index=index,
                        timestamp=timestamp,
                        hostname=str(
                            row.get("hostname") or target.hostname
                        ),
                        raw_reference=raw_reference,
                    )
                )
        return tuple(records)

    def _manifest_timestamps(self, case_id: str) -> dict[str, datetime]:
        path = self.repository.paths(case_id).manifest_json
        if not path.is_file():
            return {}
        try:
            manifest = EvidenceManifest.from_dict(read_json_object(path))
        except (JsonFileError, KeyError, TypeError, ValueError) as exc:
            raise ProcessingError(
                f"Không thể đọc thời điểm live data từ manifest: {exc}"
            ) from exc
        return {
            item.stored_path: item.collected_at
            for item in manifest.evidence_items
            if item.category.value == "live"
        }

    @staticmethod
    def _rows(value: Any, collector_id: str, path: Path) -> tuple[dict, ...]:
        if collector_id == "system":
            if not isinstance(value, dict):
                raise ProcessingError(
                    f"{path.name} phải chứa JSON object."
                )
            return (dict(value),)
        if not isinstance(value, list) or any(
            not isinstance(item, dict) for item in value
        ):
            raise ProcessingError(
                f"{path.name} phải chứa JSON array các object."
            )
        return tuple(dict(item) for item in value)

    @staticmethod
    def _record(
        *,
        case_id: str,
        collector_id: str,
        artifact_type: ArtifactType,
        row: dict[str, Any],
        index: int,
        timestamp: datetime,
        hostname: str,
        raw_reference: str,
    ) -> NormalizedRecord:
        attributes = dict(row)
        common = {
            "case_id": case_id,
            "source_type": _LIVE_SOURCE_TYPES[collector_id],
            "artifact_type": artifact_type,
            "timestamp": timestamp,
            "record_id": _record_id(
                case_id,
                raw_reference,
                index,
                row,
            ),
            "hostname": hostname,
            "raw_reference": raw_reference,
            "attributes": attributes,
        }

        if collector_id == "system":
            return NormalizedRecord(
                **common,
                summary=f"Live system snapshot: {hostname}",
                user=str(row.get("current_user") or ""),
            )
        if collector_id == "users":
            user = str(row.get("name") or "")
            return NormalizedRecord(
                **common,
                summary=f"Local user account: {user or 'unknown'}",
                user=user,
            )
        if collector_id == "processes":
            name = str(row.get("name") or "")
            return NormalizedRecord(
                **common,
                summary=f"Running process: {name or 'unknown'}",
                user=str(row.get("owner") or ""),
                process_name=name,
                process_id=_integer(row.get("pid")),
                parent_process_id=_integer(row.get("parent_pid")),
                file_path=str(row.get("executable_path") or ""),
            )
        if collector_id == "network":
            protocol = str(row.get("protocol") or "network").upper()
            local = str(row.get("local_address") or "")
            remote = str(row.get("remote_address") or "")
            local_port = row.get("local_port")
            remote_port = row.get("remote_port")
            return NormalizedRecord(
                **common,
                summary=(
                    f"Live {protocol} connection: "
                    f"{local}:{local_port} -> {remote}:{remote_port}"
                ),
                process_id=_integer(row.get("pid")),
                source_ip=local,
                destination_ip=remote,
            )
        if collector_id == "services":
            name = str(row.get("name") or "")
            state = str(row.get("state") or "unknown")
            attributes.setdefault("service_name", name)
            return NormalizedRecord(
                **{**common, "attributes": attributes},
                summary=f"Windows service {name or 'unknown'}: {state}",
                user=str(row.get("start_name") or ""),
                process_id=_integer(row.get("process_id")),
                file_path=str(row.get("path_name") or ""),
            )

        name = str(row.get("name") or "")
        command = str(row.get("command") or "")
        return NormalizedRecord(
            **common,
            summary=(
                f"Startup entry {name or 'unknown'}"
                + (f": {command}" if command else "")
            ),
            user=str(row.get("user") or ""),
        )


def _integer(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_id(
    case_id: str,
    raw_reference: str,
    index: int,
    row: dict[str, Any],
) -> str:
    canonical = json.dumps(
        row,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(
        f"{case_id}\0{raw_reference}\0{index}\0{canonical}".encode("utf-8")
    ).hexdigest()
    return f"REC-LIVE-{digest[:24]}"
