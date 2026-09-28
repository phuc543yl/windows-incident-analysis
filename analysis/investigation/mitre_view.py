"""Aggregate MITRE ATT&CK coverage for one Case."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from models.alert import Alert
from models.finding import Finding


def build_mitre_summary(
    alerts: tuple[Alert, ...] = (),
    findings: tuple[Finding, ...] = (),
) -> dict[str, Any]:
    techniques: dict[str, dict[str, Any]] = {}
    tactics: dict[str, int] = defaultdict(int)
    for alert in alerts:
        mappings = alert.details.get("mitre_mapping") or ()
        if mappings:
            for mapping in mappings:
                technique_id = str(mapping.get("technique_id", "")).strip()
                if not technique_id:
                    continue
                bucket = techniques.setdefault(
                    technique_id,
                    {
                        "technique_id": technique_id,
                        "technique_name": mapping.get("technique_name", ""),
                        "tactics": list(mapping.get("tactics", ())),
                        "alert_count": 0,
                        "finding_count": 0,
                    },
                )
                bucket["alert_count"] += 1
                for tactic in mapping.get("tactics", ()):
                    tactics[str(tactic)] += 1
        else:
            for technique_id in alert.mitre_techniques:
                bucket = techniques.setdefault(
                    technique_id,
                    {
                        "technique_id": technique_id,
                        "technique_name": "",
                        "tactics": [],
                        "alert_count": 0,
                        "finding_count": 0,
                    },
                )
                bucket["alert_count"] += 1
    for finding in findings:
        for technique_id in finding.mitre_techniques:
            bucket = techniques.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "technique_name": "",
                    "tactics": [],
                    "alert_count": 0,
                    "finding_count": 0,
                },
            )
            bucket["finding_count"] += 1
    rows = tuple(
        sorted(
            techniques.values(),
            key=lambda item: (
                -int(item["alert_count"]),
                item["technique_id"],
            ),
        )
    )
    return {
        "schema_version": 1,
        "technique_count": len(rows),
        "techniques": list(rows),
        "tactics": [
            {"tactic": name, "count": count}
            for name, count in sorted(
                tactics.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ],
    }
