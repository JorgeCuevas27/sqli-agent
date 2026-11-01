from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATASETS = Path(__file__).resolve().parent.parent / "datasets"

_DEFAULT_LADDER: tuple[tuple[str, ...], ...] = (
    (), ("case",), ("inline_comment",), ("inline_comment", "case"),
    ("union_all", "case"), ("union_all", "inline_comment", "case"),
    ("versioned_comment",), ("versioned_comment", "case"),
    ("term_hash", "inline_comment", "case"), ("whitespace_tab",),
    ("whitespace_newline",), ("whitespace_tab", "case"),
    ("union_all", "versioned_comment", "case"), ("double_keyword",),
    ("double_keyword", "inline_comment", "case"),
)


def _load(name: str) -> dict[str, Any]:
    try:
        return json.loads((_DATASETS / name).read_text(encoding="utf-8"))
    except Exception:
        return {}


def bypass_ladder() -> tuple[tuple[str, ...], ...]:
    raw = _load("sqli_kb.json").get("waf_bypass_ladder")
    if not raw:
        return _DEFAULT_LADDER
    try:
        return tuple(tuple(step) for step in raw)
    except Exception:
        return _DEFAULT_LADDER


def extraction_techniques() -> dict[str, list[str]]:
    return _load("sqli_kb.json").get("extraction_techniques", {})


def technique_names() -> list[str]:
    return list(extraction_techniques().keys())


def fill(template: str, **fields: str) -> str:
    out = template
    for key, value in fields.items():
        out = out.replace("{" + key + "}", str(value))
    return out



_CORPUS = _DATASETS / "corpus"
_CATEGORY = {
    "Generic_UnionSelect": "union",
    "Generic_ErrorBased": "error-based",
    "Generic_TimeBased": "time-based",
    "Generic_Fuzz": "detection",
    "SQLi_Polyglots": "detection",
    "patt_auth_bypass": "boolean-blind",
    "Auth_Bypass": "boolean-blind",
    "Auth_Bypass2": "boolean-blind",
    "FUZZDB_MYSQL": "mysql",
}


def corpus() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not _CORPUS.is_dir():
        return out
    for path in sorted(_CORPUS.glob("*.txt")):
        category = _CATEGORY.get(path.stem, "other")
        try:
            lines = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
        except Exception:
            lines = []
        out.setdefault(category, []).extend(lines)
    return out


def corpus_size() -> int:
    return sum(len(v) for v in corpus().values())


def detection_payloads(limit: int = 6) -> list[str]:
    det = corpus().get("detection", [])
    return (det or ["'", "''", "`", "1'1", "'\"", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"])[:limit]


def corpus_payloads(technique: str, limit: int = 20) -> list[str]:
    return corpus().get(technique, [])[:limit]



_WORDLISTS = _DATASETS / "wordlists"
_USER_HINTS = ("user", "login", "uname", "name", "email", "mail", "account", "member", "nick")
_PASS_HINTS = ("pass", "pwd", "secret", "hash", "token", "credential", "salt", "auth")


def _load_wordlist(name: str) -> list[str]:
    path = _WORDLISTS / name
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    out, seen = [], set()
    for ln in raw:
        w = ln.strip()
        if not w or w.startswith("#"):
            continue
        key = w.lower()
        if key not in seen:
            seen.add(key)
            out.append(w)
    return out


def common_columns() -> list[str]:
    return _load_wordlist("common-columns.txt")


def common_tables() -> list[str]:
    return _load_wordlist("common-tables.txt")


def _prioritize(columns: list[str], hints: tuple[str, ...], cap: int) -> list[str]:
    exact, partial, seen = [], [], set()
    for c in columns:
        cl = c.lower()
        bucket = exact if cl in hints else (partial if any(h in cl for h in hints) and "id" not in cl else None)
        if bucket is not None and cl not in seen:
            seen.add(cl)
            bucket.append(c)
    return (exact + partial)[:cap]


def credential_column_candidates(cap: int = 120) -> tuple[list[str], list[str]]:
    cols = common_columns()
    if not cols:
        return (["user", "username", "login", "name", "email"],
                ["password", "pass", "pwd", "passwd", "secret", "hash"])
    return _prioritize(cols, _USER_HINTS, cap), _prioritize(cols, _PASS_HINTS, cap)
