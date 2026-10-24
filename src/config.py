"""Central configuration for the SQLi agent. Values can be overridden via environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    # Target (DVWA running locally via docker-compose)
    dvwa_url: str = os.getenv("DVWA_URL", "http://192.168.56.101")
    dvwa_user: str = os.getenv("DVWA_USER", "admin")
    dvwa_password: str = os.getenv("DVWA_PASSWORD", "password")

    # LLM brain (local Ollama)
    ollama_url: str = os.getenv("OLLAMA_URL", "http://192.168.56.101:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

    # Run limits
    max_steps: int = int(os.getenv("MAX_STEPS", "80"))  # el descubrimiento + evasión de WAF usa varios sondeos
    timeout_seconds: int = int(os.getenv("TIMEOUT_SECONDS", "600"))  # cap per run; human baseline ~10 min


CONFIG = Config()
