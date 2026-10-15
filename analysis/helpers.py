"""Shared field extraction and deterministic identifiers for analysis."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from common.enums import ArtifactType
from models.normalized_record import NormalizedRecord

_KEY_PATTERN = re.compile(r"[^a-z0-9]+")


def normalized_key(value: Any) -> str:
    return _KEY_PATTERN.sub("", str(value).strip().casefold())


def attribute(
    record: NormalizedRecord,
    *names: str,
    default: Any = "",
) -> Any:
    values = {normalized_key(key): value for key, value in record.attributes.items()}
    for name in names:
        value = values.get(normalized_key(name))
        if value not in (None, ""):
            return value
    return default


def text_blob(record: NormalizedRecord) -> str:
    values = (
        record.summary,
        record.user,
        record.process_name,
        record.file_path,
        record.source_ip,
        record.destination_ip,
        json.dumps(
            record.attributes,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        ),
    )
    return (
        " ".join(str(value) for value in values)
        .casefold()
        .replace(
            "\\",
            "/",
        )
    )


def conceptual_source(record: NormalizedRecord) -> str:
    mapping = {
        ArtifactType.EVENT_LOGS: "event_log",
        ArtifactType.PROCESSES: "process",
        ArtifactType.NETWORK: "network",
        ArtifactType.REGISTRY: "registry",
        ArtifactType.SCHEDULED_TASKS: "scheduled_task",
        ArtifactType.SERVICES: "service",
        ArtifactType.PREFETCH: "prefetch",
        ArtifactType.AMCACHE: "amcache",
        ArtifactType.MFT: "mft",
        ArtifactType.FILES: "file",
    }
    return mapping.get(record.artifact_type, record.source_type)


def source_allowed(
    record: NormalizedRecord,
    allowed: Iterable[str],
) -> bool:
    normalized = {str(value).strip().casefold() for value in allowed}
    return (
        conceptual_source(record).casefold() in normalized
        or record.source_type.casefold() in normalized
    )


def target_user(record: NormalizedRecord) -> str:
    if "target_user" in record.attributes:
        return str(record.attributes["target_user"] or "").strip()
    names = ("target_user", "target_user_name", "targetusername")
    if record.event_id not in {4624, 4625}:
        names = (*names, "subject_user_name")
    return str(
        attribute(
            record,
            *names,
            default=record.user,
        )
    ).strip()


def source_ip(record: NormalizedRecord) -> str:
    if "source_ip" in record.attributes:
        return str(record.attributes["source_ip"] or "").strip()
    return str(
        attribute(
            record,
            "source_ip",
            "src_ip",
            "ip_address",
            "ipaddress",
            default=record.source_ip,
        )
    ).strip()


def service_name(record: NormalizedRecord) -> str:
    return str(
        attribute(
            record,
            "service_name",
            "servicename",
            "param1",
            default="",
        )
    ).strip()


def integer_attribute(
    record: NormalizedRecord,
    *names: str,
) -> int | None:
    value = attribute(record, *names, default=None)
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


def deterministic_id(
    prefix: str,
    *parts: Any,
    length: int = 32,
) -> str:
    payload = "\0".join(str(part) for part in parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{prefix.upper()}-{digest[:length]}"


def unique_strings(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def authorized_maintenance(record: NormalizedRecord) -> bool:
    """True when the record itself marks an approved/change-window action."""
    flags = (
        attribute(record, "authorized", "approved", "change_approved"),
        attribute(record, "maintenance", "in_change_window"),
    )
    return any(
        str(value).strip().casefold() in {"1", "true", "yes", "approved"}
        for value in flags
        if value not in (None, "")
    )


def maintenance_authorization(record: NormalizedRecord) -> bool | None:
    """Keep unknown approval context distinct from an explicit rejection."""
    if authorized_maintenance(record):
        return True
    flags = (attribute(record, "authorized", "approved", "change_approved"),)
    if any(
        str(value).strip().casefold()
        in {"0", "false", "no", "unauthorized", "rejected"}
        for value in flags
        if value not in (None, "")
    ):
        return False
    return None


def file_hashes(record: NormalizedRecord) -> tuple[str, str]:
    before = (
        str(
            attribute(
                record,
                "hash_before",
                "sha256_before",
                "baseline_sha256",
                default="",
            )
        )
        .strip()
        .casefold()
    )
    after = (
        str(
            attribute(
                record,
                "hash_after",
                "sha256_after",
                "current_sha256",
                default="",
            )
        )
        .strip()
        .casefold()
    )
    return before, after


def probe_status(record: NormalizedRecord) -> str:
    return (
        str(
            attribute(
                record,
                "probe_status",
                "availability_status",
                "service_probe",
                default="",
            )
        )
        .strip()
        .casefold()
    )
