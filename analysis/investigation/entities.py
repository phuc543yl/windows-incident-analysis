"""Pivot normalized records by user, IP, process, or file."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from models.normalized_record import NormalizedRecord
from analysis.helpers import source_ip, target_user


@dataclass(frozen=True, slots=True)
class EntityIndex:
    users: tuple[str, ...]
    ips: tuple[str, ...]
    processes: tuple[str, ...]
    files: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "users": list(self.users),
            "ips": list(self.ips),
            "processes": list(self.processes),
            "files": list(self.files),
        }


def build_entity_index(
    records: tuple[NormalizedRecord, ...],
) -> EntityIndex:
    users = {target_user(record) for record in records if target_user(record)}
    ips = set()
    for record in records:
        if source_ip(record):
            ips.add(source_ip(record))
        if record.destination_ip:
            ips.add(record.destination_ip)
    processes = {
        record.process_name
        for record in records
        if record.process_name
    }
    files = {record.file_path for record in records if record.file_path}
    return EntityIndex(
        users=tuple(sorted(users, key=str.casefold)),
        ips=tuple(sorted(ips)),
        processes=tuple(sorted(processes, key=str.casefold)),
        files=tuple(sorted(files, key=str.casefold)),
    )


def pivot_entities(
    records: tuple[NormalizedRecord, ...],
    *,
    entity_type: str,
    value: str,
) -> tuple[NormalizedRecord, ...]:
    needle = value.strip().casefold()
    if not needle:
        return ()
    kind = entity_type.strip().casefold()
    matched: list[NormalizedRecord] = []
    for record in records:
        haystacks = []
        if kind in {"user", "users"}:
            haystacks.append(target_user(record))
            haystacks.append(record.user)
        elif kind in {"ip", "ips"}:
            haystacks.extend(
                (
                    source_ip(record),
                    record.source_ip,
                    record.destination_ip,
                )
            )
        elif kind in {"process", "processes"}:
            haystacks.append(record.process_name)
        elif kind in {"file", "files"}:
            haystacks.append(record.file_path)
        else:
            haystacks.extend(
                (
                    target_user(record),
                    source_ip(record),
                    record.process_name,
                    record.file_path,
                )
            )
        if any(needle in str(item).casefold() for item in haystacks if item):
            matched.append(record)
    return tuple(matched)
