"""Model describing the Windows endpoint under investigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any

from models import new_id, require_non_empty, string_tuple, to_json_value


@dataclass(slots=True)
class TargetHost:
    hostname: str
    host_id: str = field(default_factory=lambda: new_id("HOST"))
    ip_addresses: tuple[str, ...] = ()
    os_name: str = ""
    os_version: str = ""
    architecture: str = ""
    domain: str = ""
    current_user: str = ""
    agent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.hostname = require_non_empty(self.hostname, "hostname")
        self.host_id = require_non_empty(self.host_id, "host_id")
        self.ip_addresses = string_tuple(self.ip_addresses)
        for address in self.ip_addresses:
            try:
                ip_address(address)
            except ValueError as exc:
                raise ValueError(f"Địa chỉ IP không hợp lệ: {address}") from exc
        if self.agent_id is not None:
            self.agent_id = require_non_empty(self.agent_id, "agent_id")
        self.metadata = dict(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return to_json_value(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetHost":
        return cls(
            hostname=data["hostname"],
            host_id=data.get("host_id") or new_id("HOST"),
            ip_addresses=tuple(data.get("ip_addresses", ())),
            os_name=data.get("os_name", ""),
            os_version=data.get("os_version", ""),
            architecture=data.get("architecture", ""),
            domain=data.get("domain", ""),
            current_user=data.get("current_user", ""),
            agent_id=data.get("agent_id"),
            metadata=dict(data.get("metadata", {})),
        )
