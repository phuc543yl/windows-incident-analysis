"""Detect newly created Scheduled Tasks that require review."""

from __future__ import annotations

from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.rules.base_rule import BaseRule
from analysis.helpers import conceptual_source, target_user, text_blob


class ScheduledTaskCreatedRule(BaseRule):
    rule_id = "scheduled_task_created"
    recommendation = (
        "Kiểm tra XML của task, creator, action, trigger và lịch sử chạy."
    )

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
    ) -> tuple[Alert, ...]:
        event_ids = {
            int(value)
            for value in self.parameters.get("event_ids", ())
        }
        indicators = tuple(
            str(value).casefold()
            for value in self.parameters.get(
                "suspicious_action_indicators",
                (),
            )
        )
        review_system = bool(
            self.parameters.get("review_system_tasks", True)
        )
        alerts: list[Alert] = []
        for record in self.candidates(records):
            blob = text_blob(record)
            hits = tuple(value for value in indicators if value in blob)
            is_creation_event = record.event_id in event_ids
            is_task_source = (
                conceptual_source(record) == "scheduled_task"
            )
            if not is_creation_event and not is_task_source:
                continue
            collapsed = "/".join(
                part for part in blob.replace("\\", "/").split("/") if part
            )
            if "microsoft/windows/" in f"{collapsed}/":
                continue
            is_system = target_user(record).casefold() in {
                "system",
                "nt authority/system",
            }
            if not (
                is_creation_event
                or hits
                or (review_system and is_system)
            ):
                continue
            alerts.append(
                self.alert(
                    (record,),
                    findings,
                    details={
                        "action_indicator_hits": hits,
                        "runs_as_system": is_system,
                    },
                    indicator_hits=len(hits),
                )
            )
        return tuple(alerts)
