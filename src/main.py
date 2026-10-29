"""CLI entry point: run one SQLi attack against a DVWA level and record the result.

    python -m src.main --level low

Operates ONLY against the local DVWA configured in config.py."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from rich.console import Console

from .config import CONFIG
from .dvwa import DVWAClient
from .llm import OllamaClient
from .orchestrator import Orchestrator
from .types import RunResult

_RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def _result_to_dict(result: RunResult) -> dict:
    return {
        "level": result.level,
        "success": result.success,
        "elapsed_seconds": result.elapsed_seconds,
        "steps_used": result.steps_used,
        "strategy": result.strategy,
        "waf_profile": result.waf_profile,
        "discovery_trace": result.trace,
        "extracted": result.extracted,
        "payloads": result.payloads,
        "attempts": [
            {
                "step": a.step,
                "payload": a.payload,
                "reason": a.reason,
                "http_status": a.response.http_status,
                "db_error": a.response.db_error,
                "rows_parsed": a.response.rows,
                "analysis": a.analysis,
            }
            for a in result.attempts
        ],
    }


def _write_payloads_txt(path: Path, result: RunResult, target: str) -> None:
    """Exporta un .txt legible con los payloads de la corrida, para pruebas manuales (Burp)."""
    passed, blocked, seen_p, seen_b = [], [], set(), set()
    for e in result.payloads:
        p = e["payload"]
        if e["blocked"]:
            if p not in seen_b:
                seen_b.add(p); blocked.append(e)
        elif p not in seen_p:
            seen_p.add(p); passed.append(e)

    L = ["=" * 64,
         "SQLi-Agent — payloads de la corrida (para pruebas manuales)",
         f"Nivel: {result.level}   Objetivo: {target}   "
         f"Resultado: {'SUCCESS' if result.success else 'FAILED'}",
         f"Enviados: {len(result.payloads)}   distintos que PASARON el WAF: {len(passed)}   "
         f"distintos BLOQUEADOS: {len(blocked)}",
         "=" * 64, "",
         "### PAYLOADS QUE PASARON EL WAF (pruébalos aquí) ###"]
    L += [e["payload"] for e in passed[:80]]
    if len(passed) > 80:
        L.append(f"... (+{len(passed) - 80} más; el log completo está en el JSON)")
    L += ["", "### PAYLOADS BLOQUEADOS POR EL WAF (muestra) ###"]
    L += [f"[HTTP {e['http_status']}] {e['payload']}" for e in blocked[:30]]
    if len(blocked) > 30:
        L.append(f"... (+{len(blocked) - 30} más)")
    L += ["", "### CREDENCIALES EXTRAÍDAS ###"]
    L += [str(c) for c in result.extracted] or ["(ninguna)"]
    path.write_text("\n".join(L), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-agent SQLi attacker for a local DVWA lab")
    parser.add_argument("--level", default="low", choices=["low", "medium", "high"])
    parser.add_argument("--max-steps", type=int, default=CONFIG.max_steps)
    parser.add_argument("--timeout", type=int, default=CONFIG.timeout_seconds)
    args = parser.parse_args()

    console = Console()
    console.rule(f"SQLi-Agent — DVWA level = {args.level}")
    console.print(f"[dim]target={CONFIG.dvwa_url}  model={CONFIG.ollama_model}[/dim]")

    orchestrator = Orchestrator(OllamaClient(), DVWAClient())
    try:
        result = orchestrator.run(
            level=args.level,
            max_steps=args.max_steps,
            timeout_seconds=args.timeout,
            log=lambda msg: console.print(msg),
        )
    except Exception as exc:  # red caída, WAF que no responde, Ollama caído: sale limpio, sin traza
        console.rule("Result")
        console.print(f"[red]ABORTED[/red]  level={args.level}  ({type(exc).__name__}: {exc})")
        console.print("[dim]Revisa que el contenedor del objetivo y Ollama estén arriba y "
                      "respondiendo, y reintenta.[/dim]")
        raise SystemExit(1)

    console.rule("Result")
    verdict = "[green]SUCCESS[/green]" if result.success else "[red]FAILED[/red]"
    console.print(f"{verdict}  level={result.level}  time={result.elapsed_seconds}s  steps={result.steps_used}")
    if result.extracted:
        console.print("Extracted credentials:")
        for cred in result.extracted:
            console.print(f"  - {cred}")

    _RESULTS_DIR.mkdir(exist_ok=True)
    stamp = int(time.time())
    out = _RESULTS_DIR / f"run_{args.level}_{stamp}.json"
    out.write_text(json.dumps(_result_to_dict(result), indent=2), encoding="utf-8")
    console.print(f"[dim]saved {out}[/dim]")

    payloads_txt = _RESULTS_DIR / f"payloads_{args.level}_{stamp}.txt"
    _write_payloads_txt(payloads_txt, result, CONFIG.dvwa_url)
    console.print(f"[dim]payloads para pruebas manuales -> {payloads_txt}[/dim]")


if __name__ == "__main__":
    main()
