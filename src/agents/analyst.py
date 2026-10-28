"""Analyst: dada una tabla y sus columnas descubiertas, decide cuáles son las credenciales.
También PROPONE nombres de columnas de credencial cuando el esquema no se puede enumerar (ruta
ciega): ahí la "inteligencia" de qué nombre es usuario/password viene del LLM, no de una lista."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .base import Agent
from ..llm import parse_json

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


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

    def guess_credential_columns(self) -> tuple[list[str], list[str]]:
        """El LLM PROPONE nombres probables de columnas de usuario y password (sin ver el esquema).
        Devuelve (usuarios, passwords) deduplicados, tal como los razonó el modelo. El que llama los
        aterriza en una wordlist real (sqlmap) antes de usarlos."""
        system = (_PROMPTS_DIR / "analyst_columns.md").read_text(encoding="utf-8")
        raw = self.llm.chat(system, "List the likely credential column names.",
                            json_mode=True, temperature=0.2)
        data = parse_json(raw)

        def names(key: str) -> list[str]:
            seen, out = set(), []
            for x in data.get(key, []) or []:
                s = str(x).strip()
                if s and s.lower() not in seen:
                    seen.add(s.lower())
                    out.append(s)
            return out

        return names("username_columns"), names("password_columns")
