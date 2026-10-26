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
import statistics
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
                console.print(f"[dim]({done}/{total}) {scen} · {level} · corrida {i}/{args.runs}...[/dim]")
                res = run_one(url, level)
                rows.append({"scenario": scen, "level": level, "run": i, **res})

    _RESULTS.mkdir(exist_ok=True)
    out = _RESULTS / f"experiments_{int(time.time())}.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["scenario", "level", "run", "success", "time", "steps", "error"])
        writer.writeheader()
        writer.writerows(rows)

    # tabla resumen: tasa de éxito + tiempo/pasos promedio (solo de corridas exitosas)
    console.rule("Resumen — tasa de éxito y time-to-exploit")
    console.print(f"[bold]{'escenario':<14}{'nivel':<8}{'éxito':<8}{'t medio(s)':<12}{'pasos medio':<12}[/bold]")
    for scen in scenarios:
        for level in levels:
            cell = [r for r in rows if r["scenario"] == scen and r["level"] == level]
            ok = [r for r in cell if r["success"]]
            rate = f"{len(ok)}/{len(cell)}"
            tmean = f"{statistics.mean([r['time'] for r in ok]):.2f}" if ok else "—"
            smean = f"{statistics.mean([r['steps'] for r in ok]):.1f}" if ok else "—"
            console.print(f"{scen:<14}{level:<8}{rate:<8}{tmean:<12}{smean:<12}")
    console.print(f"\n[dim]CSV guardado en: {out}[/dim]")


if __name__ == "__main__":
    main()
