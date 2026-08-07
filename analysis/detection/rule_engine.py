from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from common.exceptions import AnalysisError, JsonFileError
from common.json_utils import read_json_object
from common.paths import config_dir, project_root
from models.alert import Alert
from models.finding import Finding
from models.normalized_record import NormalizedRecord
from analysis.detection.mitre_mapper import MitreMapper
from analysis.detection.risk_engine import RiskEngine
from analysis.detection.rules import RULE_TYPES, BaseRule


class RuleEngine:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        config_path: str | Path | None = None,
        mapper: MitreMapper | None = None,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self.project = project_root(root)
        self.config_path = (
            Path(config_path).expanduser().resolve()
            if config_path is not None
            else config_dir(self.project) / "detection_rules.json"
        )
        self.mapper = mapper or MitreMapper(self.project)
        self.risk_engine = risk_engine or RiskEngine()
        self.rules = self._load_rules()

    def evaluate(
        self,
        records: tuple[NormalizedRecord, ...],
        findings: tuple[Finding, ...] = (),
        *,
        rule_ids: Iterable[str] | None = None,
    ) -> tuple[Alert, ...]:
        case_ids = {record.case_id for record in records}
        if len(case_ids) > 1:
            raise AnalysisError("RuleEngine không thể xử lý nhiều Case.")
        selected = self._selected_rule_ids(rule_ids)
        alerts: list[Alert] = []
        seen: set[str] = set()
        for rule in self.rules:
            if not rule.enabled or rule.rule_id not in selected:
                continue
            for alert in rule.evaluate(records, findings):
                if alert.alert_id in seen:
                    continue
                seen.add(alert.alert_id)
                mapping = self.mapper.mappings_for(alert.rule_id)
                alert.details.setdefault("mitre_mapping", mapping)
                alerts.append(alert)
        return tuple(
            sorted(
                alerts,
                key=lambda item: (
                    item.created_at,
                    -item.risk_score,
                    item.alert_id,
                ),
            )
        )

    def _selected_rule_ids(
        self,
        rule_ids: Iterable[str] | None,
    ) -> frozenset[str]:
        available = {rule.rule_id for rule in self.rules}
        if rule_ids is None:
            return frozenset(available)
        selected = {
            str(rule_id).strip().casefold()
            for rule_id in rule_ids
            if str(rule_id).strip()
        }
        unknown = selected - available
        if unknown:
            raise AnalysisError(
                "Investigation profile chứa detection rule không tồn tại: "
                f"{sorted(unknown)}"
            )
        return frozenset(selected)

    def get(self, rule_id: str) -> BaseRule:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        raise AnalysisError(f"Không tìm thấy detection rule: {rule_id}")

    def _load_rules(self) -> tuple[BaseRule, ...]:
        try:
            data = read_json_object(self.config_path)
        except JsonFileError as exc:
            raise AnalysisError(str(exc)) from exc
        if data.get("schema_version") != 1:
            raise AnalysisError(
                "detection_rules.json có schema_version không hỗ trợ."
            )
        defaults = data.get("defaults", {})
        raw_rules = data.get("rules")
        if not isinstance(defaults, dict) or not isinstance(raw_rules, list):
            raise AnalysisError(
                "detection_rules.json không đúng cấu trúc."
            )
        rules: list[BaseRule] = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                raise AnalysisError(
                    f"Detection rule {index} phải là object."
                )
            merged = dict(defaults)
            merged.update(raw)
            rule_id = str(merged.get("id", ""))
            if rule_id in seen:
                raise AnalysisError(f"Trùng detection rule: {rule_id}")
            try:
                rule_type = RULE_TYPES[rule_id]
            except KeyError as exc:
                raise AnalysisError(
                    f"Chưa triển khai detection rule: {rule_id}"
                ) from exc
            configured_mitre = tuple(
                str(value)
                for value in merged.get("mitre_techniques", ())
            )
            self.mapper.validate_rule(rule_id, configured_mitre)
            rules.append(
                rule_type(merged, risk_engine=self.risk_engine)
            )
            seen.add(rule_id)
        return tuple(rules)
