"""Common base for the three agents: each loads its system prompt from `src/prompts/`
and talks to the shared Ollama client. Mirrors PentAGI's model of one editable prompt
template per agent role."""
from __future__ import annotations

from pathlib import Path

from ..llm import OllamaClient

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


class Agent:
    def __init__(self, name: str, prompt_file: str, llm: OllamaClient) -> None:
        self.name = name
        self.llm = llm
        self.system = (_PROMPTS_DIR / prompt_file).read_text(encoding="utf-8")
