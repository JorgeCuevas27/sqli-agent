from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SqliResponse:

    payload: str
    http_status: int
    raw_html: str
    rows: list[dict[str, str]] = field(default_factory=list)
    db_error: bool = False
    blocked: bool = False


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
    trace: list[str] = field(default_factory=list)
    waf_profile: dict[str, Any] = field(default_factory=dict)
    payloads: list[dict[str, Any]] = field(default_factory=list)
    slm_metrics: dict[str, Any] = field(default_factory=dict)
