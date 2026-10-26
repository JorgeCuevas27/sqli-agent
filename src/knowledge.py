"""Base de conocimiento del agente (RAG local, sin nube).

El agente se ALIMENTA de datasets curados —plantillas de técnicas de extracción y una escalera de
evasión de WAF (de PayloadsAllTheThings / SecLists)— y a la vez GENERA sus payloads rellenando esas
plantillas con el esquema que descubre. Todo es con respaldo determinista: si un dataset falta o
está corrupto, se usan los valores por defecto para que el agente siga siendo robusto.

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


def bypass_payloads() -> list[dict[str, str]]:
    """Payloads de evasión de WAF conocidos (munición adicional del dataset)."""
    return _load("waf_bypass_payloads.json").get("bypass_payloads", [])


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
    return corpus().get("detection", [])[:limit]
