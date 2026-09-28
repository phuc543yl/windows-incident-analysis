"""Persist analyst notes for a Case."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from case_management.case_repository import CaseRepository
from common.json_utils import read_json_object, write_json
from common.time_utils import to_iso8601, utc_now


class NotesService:
    def __init__(
        self,
        root: str | Path | None = None,
        *,
        actor: str = "analyst",
    ) -> None:
        self.repository = CaseRepository(root)
        self.actor = actor.strip() or "analyst"

    def load(self, case_id: str) -> list[dict[str, Any]]:
        case = self.repository.load_case(case_id)
        path = self.repository.paths(case.case_id).notes_json
        if not path.is_file():
            return []
        data = read_json_object(path)
        notes = data.get("notes", data.get("entries", []))
        if not isinstance(notes, list):
            return []
        return [dict(item) if isinstance(item, dict) else {"text": str(item)} for item in notes]

    def add(self, case_id: str, text: str) -> list[dict[str, Any]]:
        note_text = text.strip()
        if not note_text:
            raise ValueError("Ghi chú không được để trống.")
        case = self.repository.require_open(case_id)
        notes = self.load(case.case_id)
        notes.append(
            {
                "timestamp": to_iso8601(utc_now()),
                "actor": self.actor,
                "text": note_text,
            }
        )
        write_json(
            self.repository.paths(case.case_id).notes_json,
            {
                "schema_version": 1,
                "case_id": case.case_id,
                "notes": notes,
            },
        )
        return notes
