"""Analyst: dada una tabla y sus columnas descubiertas, decide cuáles son las credenciales."""
from __future__ import annotations

import json
from typing import Optional

from .base import Agent
from ..llm import parse_json


class Analyst(Agent):
    def pick_credentials(self, table: str, columns: list[str]) -> Optional[tuple[str, str]]:
        """Devuelve (columna_usuario, columna_contraseña) elegidas por el LLM, o None."""
        request = {"table": table, "columns": columns}
        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.1)
        data = parse_json(raw)
        user_col = str(data.get("username_column", "")).strip()
        pass_col = str(data.get("password_column", "")).strip()
        if user_col and pass_col and user_col != pass_col:
            return user_col, pass_col
        return None
