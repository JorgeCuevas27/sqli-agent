"""Executor: genera el payload de extracción a partir del esquema que el agente ya descubrió."""
from __future__ import annotations

from typing import Any

from .base import Agent
from ..llm import parse_json


class Executor(Agent):
    def craft_dump(
        self,
        quote: str,
        columns: int,
        reflected: list[int],
        table: str,
        cred_columns: tuple[str, str],
    ) -> dict[str, Any]:
        """Pide al LLM el payload UNION que extrae usuario+contraseña de la tabla descubierta."""
        request = {
            "dbms": "MySQL",
            "quote_context": "string (quote with ')" if quote else "integer (no quote)",
            "column_count": columns,
            "reflected_positions": reflected,
            "table": table,
            "username_column": cred_columns[0],
            "password_column": cred_columns[1],
        }
        import json

        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.1)
        return parse_json(raw)
