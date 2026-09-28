"""Detect a tracked file whose hash changed after a lab action."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import attribute, file_hashes, text_blob


class FileIntegrityChangeRule(BaseRule):
    rule_id = "file_integrity_change"
    recommendation = (
        "Đối chiếu hash trước/sau, tiến trình ghi file và Scheduled Task "
        "liên quan trước khi xác nhận Integrity."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        alerts: list[Alert] = []
        for record in self.candidates(records):
            before, after = file_hashes(record)
            flagged = str(
                attribute(
                    record,
                    "integrity_changed",
                    "hash_changed",
                    default="",
                )
            ).strip().casefold() in {"1", "true", "yes"}
            blob = text_blob(record)
            if "hash changed" in blob or "sha-256 changed" in blob:
                flagged = True
            if before and after and before != after:
                flagged = True
            if not flagged:
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "file_path": record.file_path,
                        "hash_before": before,
                        "hash_after": after,
                    },
                    indicator_hits=1,
                )
            )
        return tuple(alerts)
