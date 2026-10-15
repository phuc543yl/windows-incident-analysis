"""Count native Windows events while retaining every tool representation."""

from __future__ import annotations

import ntpath
from collections.abc import Iterable

from analysis.helpers import attribute, integer_attribute
from common.enums import ArtifactType
from models.normalized_record import NormalizedRecord


def group_windows_events(
    records: Iterable[NormalizedRecord],
) -> tuple[tuple[NormalizedRecord, ...], ...]:
    """Group only rows with a complete, matching native event identity.

    Missing IDs/channel/source paths never justify merging by timestamp alone.
    Hayabusa's default timestamp precision is milliseconds, so compare at the
    common precision along with the native ID, host, channel and EVTX path.
    """
    groups: dict[tuple, list[NormalizedRecord]] = {}
    for index, record in enumerate(records):
        key = _identity(record) or ("unidentified", index)
        groups.setdefault(key, []).append(record)
    return tuple(tuple(group) for group in groups.values())


def _identity(record: NormalizedRecord) -> tuple | None:
    native_id = integer_attribute(
        record, "event_record_id", "EventRecordId", "RecordID"
    )
    channel = str(attribute(record, "channel")).strip().casefold()
    channel = {"sec": "security", "sys": "system"}.get(channel, channel)
    source = str(
        attribute(record, "source_event_file", "SourceFile", "EvtxFile")
    ).strip()
    host = record.hostname.strip().casefold()
    if (
        record.artifact_type != ArtifactType.EVENT_LOGS
        or record.event_id is None
        or native_id is None
        or native_id <= 0
        or channel in {"", "-", "n/a"}
        or source in {"", "-", "n/a"}
        or not host
    ):
        return None
    return (
        record.case_id,
        host,
        channel,
        ntpath.normpath(source).casefold(),
        record.event_id,
        native_id,
        record.timestamp.isoformat(timespec="milliseconds"),
    )
