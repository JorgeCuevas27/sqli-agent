"""Executor: picks/adapts the single concrete payload to send next, given the plan,
the running history and the Analyst's last hint."""
from __future__ import annotations

import json
from typing import Any

from .base import Agent
from ..llm import parse_json


class Executor(Agent):
    def craft(
        self,
        level: str,
        strategy: str,
        candidate: Any,
        history: str,
        hint: str,
    ) -> dict[str, Any]:
        request = {
            "dvwa_security_level": level,
            "strategy": strategy,
            "suggested_candidate": candidate,
            "history": history or "none",
            "analyst_hint": hint or "none",
        }
        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.2)
        return parse_json(raw)
