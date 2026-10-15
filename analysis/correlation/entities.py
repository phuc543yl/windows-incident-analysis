"""Require positive entity matches and reject conflicting target context."""

from __future__ import annotations

from models.alert import Alert


def entity(alert: Alert, key: str) -> str:
    value = alert.details.get(key)
    if value is None:
        return ""
    return str(value).strip().replace("\\", "/").casefold()


def related_endpoint(first: Alert, second: Alert) -> bool:
    if first.case_id != second.case_id:
        return False
    host_a, host_b = entity(first, "hostname"), entity(second, "hostname")
    if host_a and host_b:
        return host_a == host_b
    # With missing hostnames, require a specific execution artifact; a common
    # user/IP alone can appear on multiple unrelated endpoints.
    return any(
        entity(first, key) and entity(first, key) == entity(second, key)
        for key in ("file_path", "process_id")
    )


def same_service(first: Alert, second: Alert) -> bool:
    if first.case_id != second.case_id:
        return False
    matched_host = False
    for key in ("hostname", "destination_ip"):
        left, right = entity(first, key), entity(second, key)
        if left and right:
            if left != right:
                return False
            matched_host = True
    if not matched_host:
        return False
    matched_service = False
    for key in ("service_name", "destination_port", "protocol"):
        left, right = entity(first, key), entity(second, key)
        if left and right:
            if left != right:
                return False
            if key in {"service_name", "destination_port"}:
                matched_service = True
    return matched_service


def shared_entities(alerts: tuple[Alert, ...]) -> tuple[str, ...]:
    shared: list[str] = []
    for key in ("target_user", "source_ip", "hostname", "file_path"):
        values = [entity(alert, key) for alert in alerts]
        known = [value for value in values if value]
        if len(known) >= 2 and len(set(known)) == 1:
            shared.append(f"{key}:{known[0]}")
    return tuple(sorted(shared))
