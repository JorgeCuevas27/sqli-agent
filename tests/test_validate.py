"""Valida que el VALIDADOR de payloads funciona: reconstruye la consulta de DVWA y mide si el
payload generado es SQL sintacticamente valido (sin tocar el WAF ni la red)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    import sqlglot  # noqa: F401
    HAS_SQLGLOT = True
except ImportError:
    HAS_SQLGLOT = False

from src.validate import reconstruct, validate_file


class Reconstruct(unittest.TestCase):
    def test_string_context_wraps_in_quotes(self):
        self.assertIn("'1'", reconstruct("1", "low"))
        self.assertIn("'1'", reconstruct("1", "high"))

    def test_numeric_context_no_quotes(self):
        self.assertTrue(reconstruct("1", "medium").rstrip().endswith("= 1"))


@unittest.skipUnless(HAS_SQLGLOT, "sqlglot no instalado")
class StaticValidation(unittest.TestCase):
    def _write(self, data: dict) -> Path:
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, f)
        f.close()
        return Path(f.name)

    def test_valid_payloads_pass(self):
        path = self._write({"level": "medium", "payloads": [
            {"payload": "-1 UNION SELECT user,password FROM users-- -", "blocked": False, "http_status": 200},
            {"payload": "1 AND 1=1-- -", "blocked": False, "http_status": 200},
        ]})
        out = validate_file(path)
        self.assertEqual(out["summary"]["distinct_payloads"], 2)
        self.assertEqual(out["summary"]["static_valid_pct"], 100.0)
        path.unlink()

    def test_broken_payload_flagged(self):
        # comilla sin cerrar -> SQL invalido
        path = self._write({"level": "low", "payloads": [
            {"payload": "1'", "blocked": True, "http_status": 403},
        ]})
        out = validate_file(path)
        self.assertEqual(out["summary"]["static_valid"], 0)
        path.unlink()

    def test_distinct_dedup(self):
        path = self._write({"level": "medium", "payloads": [
            {"payload": "1 AND 1=1-- -", "blocked": False, "http_status": 200},
            {"payload": "1 AND 1=1-- -", "blocked": False, "http_status": 200},
        ]})
        self.assertEqual(validate_file(path)["summary"]["distinct_payloads"], 1)
        path.unlink()


if __name__ == "__main__":
    unittest.main()
