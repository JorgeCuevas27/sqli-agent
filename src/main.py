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
    result = orchestrator.run(
        level=args.level,
        max_steps=args.max_steps,
        timeout_seconds=args.timeout,
        log=lambda msg: console.print(msg),
    )

    console.rule("Result")
    verdict = "[green]SUCCESS[/green]" if result.success else "[red]FAILED[/red]"
    console.print(f"{verdict}  level={result.level}  time={result.elapsed_seconds}s  steps={result.steps_used}")
    if result.extracted:
        console.print("Extracted credentials:")
        for cred in result.extracted:
            console.print(f"  - {cred}")

    _RESULTS_DIR.mkdir(exist_ok=True)
    out = _RESULTS_DIR / f"run_{args.level}_{int(time.time())}.json"
    out.write_text(json.dumps(_result_to_dict(result), indent=2), encoding="utf-8")
    console.print(f"[dim]saved {out}[/dim]")


if __name__ == "__main__":
    main()
