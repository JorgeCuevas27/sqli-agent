"""Valida los payloads que GENERÓ el agente, SIN pasar por el WAF.

Responde la pregunta del jurado: "¿cómo validas que el agente genera payloads CORRECTOS?" —
independiente de si tuvieron éxito o evadieron el WAF. Dos niveles:

  1. Sintáctico (estático, sqlglot): reconstruye la consulta vulnerable de DVWA con el payload
     inyectado y la parsea en dialecto MySQL. Mide el % de payloads que son SQL válido.
  2. Dinámico (opcional, --db): ejecuta la consulta reconstruida contra un MySQL real y comprueba
     que corre sin error. Requiere acceso a la BD (variables DB_HOST/DB_PORT/DB_USER/DB_PASS/DB_NAME).

Uso:
    python -m src.validate results/run_medium_1793....json
    python -m src.validate results/run_medium_1793....json --db --save
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Optional


def reconstruct(payload: str, level: str) -> str:
    """Mete el payload en la consulta vulnerable de DVWA, según el contexto del nivel."""
    base = "SELECT first_name, surname FROM users WHERE user_id = "
    if level in ("low", "high"):     # contexto de cadena (entre comillas)
        return base + f"'{payload}'"
    return base + f"{payload}"       # medium: contexto numérico (sin comillas)


def static_valid(query: str) -> bool:
    """True si la consulta reconstruida parsea como SQL de MySQL (sqlglot)."""
    import sqlglot
    try:
        sqlglot.parse_one(query, read="mysql")
        return True
    except Exception:
        return False


def _distinct_payloads(data: dict) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for e in data.get("payloads", []):
        p = e.get("payload", "")
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _db_conn():
    try:
        import pymysql  # type: ignore
    except ImportError:
        print("pymysql no instalado (pip install pymysql) — se omite la validación dinámica")
        return None
    try:
        return pymysql.connect(
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASS", ""),
            database=os.getenv("DB_NAME", "dvwa"),
            connect_timeout=5,
        )
    except Exception as exc:
        print(f"no se pudo conectar a MySQL ({exc}) — se omite la validación dinámica")
        return None


def _dynamic_valid(conn, query: str) -> bool:
    """True si la consulta se ejecuta en MySQL sin error de sintaxis (solo lectura)."""
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            cur.fetchall()
        return True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return False


def validate_file(path: Path, use_db: bool = False) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    level = data.get("level", "low")
    payloads = _distinct_payloads(data)
    conn = _db_conn() if use_db else None
    rows = []
    for p in payloads:
        q = reconstruct(p, level)
        rows.append({
            "payload": p,
            "query": q,
            "static_valid": static_valid(q),
            "db_valid": _dynamic_valid(conn, q) if conn else None,
        })
    if conn:
        conn.close()

    n = len(rows) or 1
    s_valid = sum(1 for r in rows if r["static_valid"])
    summary = {
        "level": level,
        "distinct_payloads": len(rows),
        "static_valid": s_valid,
        "static_valid_pct": round(100 * s_valid / n, 1),
    }
    if conn is not None:
        d_valid = sum(1 for r in rows if r["db_valid"])
        summary["db_valid"] = d_valid
        summary["db_valid_pct"] = round(100 * d_valid / n, 1)
    return {"summary": summary, "rows": rows}


def main() -> None:
    ap = argparse.ArgumentParser(description="Valida los payloads generados por el agente")
    ap.add_argument("results_json", help="archivo results/run_*.json de una corrida")
    ap.add_argument("--db", action="store_true", help="además ejecutar cada payload contra MySQL")
    ap.add_argument("--save", action="store_true", help="guardar el detalle en un .validation.json")
    args = ap.parse_args()

    out = validate_file(Path(args.results_json), use_db=args.db)
    s = out["summary"]
    print(f"Nivel: {s['level']}   payloads distintos: {s['distinct_payloads']}")
    print(f"Sintacticamente validos (sqlglot): {s['static_valid']}/{s['distinct_payloads']} "
          f"= {s['static_valid_pct']}%")
    if "db_valid_pct" in s:
        print(f"Ejecutan sin error en MySQL:       {s['db_valid']}/{s['distinct_payloads']} "
              f"= {s['db_valid_pct']}%")
    if args.save:
        dst = Path(args.results_json).with_suffix(".validation.json")
        dst.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"detalle -> {dst}")


if __name__ == "__main__":
    main()
