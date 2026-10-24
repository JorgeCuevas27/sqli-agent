"""Blacklist for the NAIVE WAF tier (the bypassable middle tier of the study).

Design note: these are plain, signature-style regexes. Unlike ModSecurity + OWASP CRS, this WAF
does NOT normalise comments and does NOT tokenise SQL semantically (no libinjection). That makes
it realistic for the many hand-rolled "regex WAFs" in the wild, and — crucially for the experiment
— bypassable by the evasion grammar: inserting comments between keywords or using UNION ALL breaks
the whitespace-based signatures, while case alone does not (the rules are case-insensitive).

This module is pure (no Flask/requests) so it can be unit-tested and imported by the proxy."""
from __future__ import annotations

import re

# Each rule targets a common SQLi signature. Kept deliberately naive.
# Firmas basadas en espacios (evadibles con comentarios /**/ o UNION ALL). A diferencia del CRS,
# aquí NO se bloquean identificadores como information_schema (no hay disfraz de superficie que los
# evada), para que el tier naive sea realmente bypasseable de punta a punta por la gramática.
_PATTERNS = (
    r"union\s+select",
    r"\bor\s+\d+\s*=\s*\d+",
    r"\band\s+\d+\s*=\s*\d+",
)
RULES = tuple(re.compile(p, re.IGNORECASE) for p in _PATTERNS)


def is_malicious(text: str) -> tuple[bool, str]:
    """Return (blocked, matched_pattern). `text` should be URL-decoded query + body."""
    for rule in RULES:
        if rule.search(text):
            return True, rule.pattern
    return False, ""
