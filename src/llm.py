"""Minimal Ollama chat client shared by every agent, plus a tolerant JSON parser.

A small local model occasionally wraps JSON in prose even under json_mode, so `parse_json`
falls back to extracting the first balanced-looking object."""
from __future__ import annotations

import json
import re
import time
from typing import Any

import requests

from .config import CONFIG


class OllamaClient:
    def __init__(self, url: str = CONFIG.ollama_url, model: str = CONFIG.ollama_model) -> None:
        self.url = url.rstrip("/")
        self.model = model
        # Costo-eficiencia del SLM: se acumula por cada llamada (Ollama reporta tokens y duración).
        self.stats = {"calls": 0, "prompt_tokens": 0, "eval_tokens": 0,
                      "latency_s": 0.0, "infer_s": 0.0}

    def chat(
        self,
        system: str,
        user: str,
        json_mode: bool = False,
        temperature: float = 0.2,
        timeout: int = 300,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_mode:
            payload["format"] = "json"
        t0 = time.monotonic()
        resp = requests.post(f"{self.url}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        # Registro de costo del SLM (prompt_eval_count/eval_count = tokens; eval_duration en ns).
        self.stats["calls"] += 1
        self.stats["latency_s"] += time.monotonic() - t0
        self.stats["prompt_tokens"] += int(data.get("prompt_eval_count", 0) or 0)
        self.stats["eval_tokens"] += int(data.get("eval_count", 0) or 0)
        self.stats["infer_s"] += int(data.get("eval_duration", 0) or 0) / 1e9
        return data["message"]["content"]

    def vram_mb(self) -> float:
        """VRAM (MB) que ocupa el modelo ahora mismo, vía /api/ps de Ollama. 0 si no se puede leer
        (p. ej. corriendo en CPU o el modelo ya descargado). No necesita acceso directo al GPU."""
        try:
            resp = requests.get(f"{self.url}/api/ps", timeout=5)
            for m in resp.json().get("models", []):
                if self.model in (m.get("model"), m.get("name")):
                    return round(int(m.get("size_vram", 0) or 0) / (1024 * 1024), 1)
        except Exception:
            pass
        return 0.0

    def metrics(self) -> dict[str, Any]:
        """Resumen de costo-eficiencia del SLM para la corrida (va al resultado)."""
        s = self.stats
        return {
            "llm_calls": s["calls"],
            "prompt_tokens": s["prompt_tokens"],
            "eval_tokens": s["eval_tokens"],
            "total_tokens": s["prompt_tokens"] + s["eval_tokens"],
            "llm_latency_s": round(s["latency_s"], 2),      # reloj de pared (incluye red)
            "llm_infer_s": round(s["infer_s"], 2),          # tiempo de inferencia que reporta Ollama
            "tokens_per_s": round(s["eval_tokens"] / s["infer_s"], 1) if s["infer_s"] else 0.0,
            "model_vram_mb": self.vram_mb(),                # consumo de GPU del modelo
        }


def parse_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {}
