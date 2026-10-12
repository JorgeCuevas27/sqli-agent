"""Analyst: inspects the DVWA response and decides whether the injection worked, whether
credentials were dumped, and what the Executor should do next."""
from __future__ import annotations

import json
from typing import Any

from .base import Agent
from ..llm import parse_json
from ..types import SqliResponse


class Analyst(Agent):
    def analyze(self, level: str, payload: str, response: SqliResponse) -> dict[str, Any]:
        request = {
            "dvwa_security_level": level,
            "payload_sent": payload,
            "http_status": response.http_status,
            "db_error_detected": response.db_error,
            "waf_blocked": response.blocked,
            "rows_parsed_from_page": response.rows,
            "html_excerpt": response.raw_html[:2000],
        }
        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.1)
        return parse_json(raw)
