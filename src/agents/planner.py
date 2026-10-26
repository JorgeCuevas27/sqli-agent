"""Planner: plantea la metodología y conoce las técnicas disponibles del dataset."""
from __future__ import annotations

import json
from typing import Any

from .base import Agent
from ..llm import parse_json
from .. import knowledge


class Planner(Agent):
    def plan(self, level: str, feedback: str = "") -> dict[str, Any]:
        request = {
            "dvwa_security_level": level,
            "feedback_from_previous_attempts": feedback or "none",
            "available_techniques": knowledge.technique_names(),  # del dataset (union, boolean, time, error)
            "goal": "Discover the schema and extract the stored credentials via SQL injection.",
        }
        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.3)
        return parse_json(raw)
