"""Shared data structures passed between the DVWA tool, the agents and the orchestrator."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SqliResponse:
    """Result of sending one payload to DVWA. `raw_html` is the full page; `rows` are the
    records parsed out of it (DVWA renders each as First name / Surname)."""

    payload: str
    http_status: int
    raw_html: str
    rows: list[dict[str, str]] = field(default_factory=list)
    db_error: bool = False
    blocked: bool = False  # the request was stopped by a WAF (e.g. ModSecurity) before reaching the DB


@dataclass
class Attempt:
    step: int
    payload: str
    reason: str
    response: SqliResponse
    analysis: dict[str, Any]


@dataclass
class RunResult:
    level: str
    success: bool
    elapsed_seconds: float
    steps_used: int
    extracted: list[dict[str, str]]
    strategy: str = ""
    attempts: list[Attempt] = field(default_factory=list)
    waf_profile: dict[str, Any] = field(default_factory=dict)  # what the run learned about the WAF
