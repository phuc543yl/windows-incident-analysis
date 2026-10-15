"""Detect suspicious PowerShell command indicators."""

from __future__ import annotations

import re

from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import attribute
from common.enums import ArtifactType
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord


class SuspiciousPowerShellRule(BaseRule):
    rule_id = "suspicious_powershell"
    recommendation = (
        "Giải mã command, kiểm tra parent process, script block và kết nối "
        "mạng liên quan."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {int(value) for value in self.parameters.get("event_ids", ())}
        names = {
            str(value).casefold() for value in self.parameters.get("process_names", ())
        }
        indicators = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "case_insensitive_indicators",
                (),
            )
        )
        minimum_hits = max(
            1,
            int(self.parameters.get("minimum_indicator_hits", 1)),
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            if (
                record.artifact_type is ArtifactType.EVENT_LOGS
                and event_ids
                and record.event_id not in event_ids
            ):
                continue
            command = str(
                attribute(
                    record,
                    "CommandLine",
                    "ProcessCommandLine",
                    "NewProcessCommandLine",
                    default=record.summary,
                )
            ).casefold()
            image = str(
                attribute(
                    record,
                    "NewProcessName",
                    "Image",
                    "ExecutablePath",
                    default=record.process_name,
                )
            )
            if not (
                _process_name(record.process_name) in names
                or _process_name(image) in names
                or _launches_powershell(command, names)
            ):
                continue
            hits = tuple(
                dict.fromkeys(
                    "-encodedcommand"
                    if indicator in {"-enc", "-encodedcommand"}
                    else indicator
                    for indicator in indicators
                    if _indicator_matches(command, indicator)
                )
            )
            if len(hits) < minimum_hits:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "indicator_hits": hits,
                        "high_risk_combo": len(hits) >= 2,
                        "process_name": record.process_name,
                        "process_id": record.process_id,
                        "parent_process_id": record.parent_process_id,
                    },
                    indicator_hits=len(hits),
                )
            )
        return tuple(alerts)


def _process_name(value: str) -> str:
    return value.strip().strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _launches_powershell(command: str, names: set[str]) -> bool:
    # Inspect the command being launched, including cmd /c and /k wrappers.
    # A word elsewhere in event metadata does not identify a PowerShell process.
    invocation = command.strip().lstrip("& ")
    wrapper = re.match(
        r'(?i)(?:"[^"\n]*cmd(?:\.exe)?"|\S*cmd(?:\.exe)?)\s+/[ck]\s+(.+)', invocation
    )
    if wrapper:
        invocation = wrapper.group(1).strip()
        if invocation.startswith('""') and invocation.endswith('"'):
            invocation = invocation[1:-1]
    executable = re.match(r'(?i)(?:"([^"\n]+)"|([^\s"\']+))', invocation)
    if executable is None:
        return False
    name = _process_name(executable.group(1) or executable.group(2))
    return name in names or f"{name}.exe" in names


def _indicator_matches(command: str, indicator: str) -> bool:
    pattern = r"\s+".join(re.escape(part) for part in indicator.split())
    if indicator.startswith("-"):
        pattern = r"(?<![\w-])" + pattern + r"(?![\w-])"
    return re.search(pattern, command) is not None
