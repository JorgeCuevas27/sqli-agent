"""Minimal Ollama chat client shared by every agent, plus a tolerant JSON parser.

A small local model occasionally wraps JSON in prose even under json_mode, so `parse_json`
falls back to extracting the first balanced-looking object."""
from __future__ import annotations

import json
import re
from typing import Any

import requests

from .config import CONFIG


class OllamaClient:
    def __init__(self, url: str = CONFIG.ollama_url, model: str = CONFIG.ollama_model) -> None:
        self.url = url.rstrip("/")
        self.model = model

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
        resp = requests.post(f"{self.url}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()["message"]["content"]


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
