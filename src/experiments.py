"""Runner de experimentos para el paper.

Corre el agente N veces por cada {escenario × nivel}, mide el time-to-exploit y la tasa de éxito,
guarda un CSV con cada corrida e imprime una tabla resumen (promedios) lista para las tablas.

Uso (en Kali, con Ollama corriendo en Windows):
    OLLAMA_URL=http://192.168.56.1:11434 python -m src.experiments --runs 5
    OLLAMA_URL=http://192.168.56.1:11434 python -m src.experiments --runs 10 --levels low,medium \\
        --scenarios sin-waf,modsec-weak
"""
from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path

from rich.console import Console

from .config import CONFIG
from .dvwa import DVWAClient
from .llm import OllamaClient
from .orchestrator import Orchestrator

# escenario -> URL del DVWA detrás de ese WAF (puertos del docker-compose)
SCENARIOS = {
    "sin-waf": "http://localhost",
    "modsec-weak": "http://localhost:8083",
    "naxsi": "http://localhost:8084",
    "crs": "http://localhost:8081",
}

_RESULTS = Path(__file__).resolve().parent.parent / "results"


def run_one(url: str, level: str) -> dict:
    orch = Orchestrator(OllamaClient(), DVWAClient(base_url=url))
    try:
        r = orch.run(level=level, max_steps=CONFIG.max_steps, timeout_seconds=CONFIG.timeout_seconds)
        return {"success": int(r.success), "time": r.elapsed_seconds, "steps": r.steps_used, "error": ""}
    except Exception as exc:  # p. ej. login bloqueado por el WAF
        return {"success": 0, "time": 0.0, "steps": 0, "error": str(exc)[:80]}


def main() -> None:
    ap = argparse.ArgumentParser(description="Experimentos de time-to-exploit del agente SQLi")
    ap.add_argument("--runs", type=int, default=5, help="corridas por celda (default 5)")
    ap.add_argument("--levels", default="low,medium,high")
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    args = ap.parse_args()

    console = Console()
    levels = [x.strip() for x in args.levels.split(",") if x.strip()]
    scenarios = [x.strip() for x in args.scenarios.split(",") if x.strip()]

    rows: list[dict] = []
    total = len(scenarios) * len(levels) * args.runs
    done = 0
    for scen in scenarios:
        url = SCENARIOS[scen]
        for level in levels:
            for i in range(1, args.runs + 1):
                done += 1
                res = run_one(url, level)
                rows.append({"scenario": scen, "level": level, "run": i, **res})
                verdict = "SUCCESS" if res["success"] else (f"ERROR({res['error']})" if res["error"] else "FAILED")
                console.print(f"({done}/{total}) {scen:<12}{level:<8}run {i:<2} -> "
                              f"{verdict:<10} time={res['time']}s steps={res['steps']}")

    _RESULTS.mkdir(exist_ok=True)
    out = _RESULTS / f"experiments_{int(time.time())}.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["scenario", "level", "run", "success", "time", "steps", "error"])
        writer.writeheader()
        writer.writerows(rows)

    console.rule("Listo")
    console.print(f"{len(rows)} corridas INDIVIDUALES guardadas (sin promediar) en:")
    console.print(f"[bold]{out}[/bold]")
    console.print("[dim]Columnas: scenario, level, run, success(1/0), time(s), steps, error — "
                  "el promedio lo calculas tú.[/dim]")


if __name__ == "__main__":
    main()
