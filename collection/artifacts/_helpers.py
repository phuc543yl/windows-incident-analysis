"""Internal helpers shared by raw-artifact collectors."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from clients.local_client import LocalClient
from collection.collector_registry import CollectorOutput
from common.exceptions import CollectionError


def collector_options(
    options: Mapping[str, Any],
    collector_id: str,
) -> dict[str, Any]:
    configured = options.get("collector_options", {})
    if not isinstance(configured, Mapping):
        raise CollectionError("collector_options phải là mapping.")
    selected = configured.get(collector_id, {})
    if not isinstance(selected, Mapping):
        raise CollectionError(
            f"collector_options.{collector_id} phải là mapping."
        )
    return dict(selected)


def run_export_script(
    client: LocalClient,
    destination: Path,
    script_body: str,
    *,
    metadata: dict[str, Any] | None = None,
) -> CollectorOutput:
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    script = (
        '$ErrorActionPreference = "Stop"\n'
        f"$Destination = {powershell_quote(str(destination))}\n"
        "New-Item -ItemType Directory -Path $Destination "
        "-Force | Out-Null\n"
        f"{script_body}\n"
    )
    response = client.execute_powershell_json(script)
    if isinstance(response, list):
        raw_files = response
        warnings: tuple[str, ...] = ()
    elif isinstance(response, dict):
        raw_files = response.get("files", [])
        raw_warnings = response.get("warnings", [])
        if not isinstance(raw_warnings, list):
            raise CollectionError(
                "Artifact collector trả về warnings không hợp lệ."
            )
        warnings = tuple(str(item) for item in raw_warnings)
    else:
        raise CollectionError(
            "Artifact collector phải trả về JSON object hoặc array."
        )
    if not isinstance(raw_files, list):
        raise CollectionError(
            "Artifact collector trả về files không hợp lệ."
        )

    files: list[Path] = []
    for value in raw_files:
        if not isinstance(value, str) or not value.strip():
            raise CollectionError(
                "Artifact collector trả về đường dẫn không hợp lệ."
            )
        path = Path(value).expanduser().resolve()
        try:
            path.relative_to(destination)
        except ValueError as exc:
            raise CollectionError(
                f"Artifact nằm ngoài thư mục đích: {path}"
            ) from exc
        if not path.is_file():
            raise CollectionError(
                f"Artifact đã báo cáo nhưng không tồn tại: {path}"
            )
        files.append(path)
    return CollectorOutput(
        files=tuple(files),
        warnings=warnings,
        metadata=metadata or {},
    )


def copy_selected_files(
    client: LocalClient,
    destination: Path,
    sources: list[str | Path],
    *,
    empty_warning: str,
    metadata: dict[str, Any] | None = None,
) -> CollectorOutput:
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if not sources:
        return CollectorOutput(
            warnings=(empty_warning,),
            metadata=metadata or {},
        )

    copied: list[Path] = []
    used_names: set[str] = set()
    for source in sources:
        source_path = Path(source).expanduser().resolve()
        name_key = source_path.name.casefold()
        if name_key in used_names:
            raise CollectionError(
                f"Trùng tên artifact đích: {source_path.name}"
            )
        used_names.add(name_key)
        copied.append(
            client.copy_file(
                source_path,
                destination / source_path.name,
                overwrite=False,
            )
        )
    return CollectorOutput(
        files=tuple(copied),
        metadata=metadata or {},
    )


def powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell_array(values: list[str]) -> str:
    return "@(" + ", ".join(powershell_quote(value) for value in values) + ")"
