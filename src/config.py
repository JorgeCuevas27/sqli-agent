from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    dvwa_url: str = os.getenv("DVWA_URL", "http://192.168.56.101")
    dvwa_user: str = os.getenv("DVWA_USER", "admin")
    dvwa_password: str = os.getenv("DVWA_PASSWORD", "password")

    ollama_url: str = os.getenv("OLLAMA_URL", "http://192.168.56.101:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

    max_steps: int = int(os.getenv("MAX_STEPS", "80"))
    timeout_seconds: int = int(os.getenv("TIMEOUT_SECONDS", "600"))


CONFIG = Config()
