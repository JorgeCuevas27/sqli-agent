"""Planner: turns the DVWA level (plus feedback) into a strategy and ordered payloads."""
from __future__ import annotations

import json
from typing import Any

from .base import Agent
from ..llm import parse_json


class Planner(Agent):
    def plan(self, level: str, feedback: str = "") -> dict[str, Any]:
        request = {
            "dvwa_security_level": level,
            "feedback_from_previous_attempts": feedback or "none",
            "goal": (
                "Extract the users table (usernames and password hashes) from the DVWA "
                "SQL Injection page."
            ),
        }
        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.3)
        return parse_json(raw)
