"""El Executor EJECUTA la técnica elegida: genera la forma ciega (validada, evade el WAF) y maneja
el BlindExtractor para extraer. Sin red: un LLM falso y un oráculo falso."""
from __future__ import annotations

import json
import re
import unittest

from src.agents.executor import Executor, _valid_blind_template


class FakeLLM:
    def __init__(self, compare: str) -> None:
        self.compare = compare

    def chat(self, system: str, user: str, **_kw) -> str:
        return json.dumps({"compare": self.compare})


def _exec(compare: str) -> Executor:
    return Executor("Executor", "executor.md", FakeLLM(compare))


class BlindTemplateValidation(unittest.TestCase):
    def test_accepts_like_hex_forms(self):
        self.assertTrue(_valid_blind_template("{col} LIKE {hex}"))
        self.assertTrue(_valid_blind_template("{col} RLIKE {hex}"))

    def test_rejects_unsafe_forms(self):
        self.assertFalse(_valid_blind_template("substring({col},1,1) LIKE {hex}"))  # substring + (
        self.assertFalse(_valid_blind_template("{col} LIKE '{hex}'"))               # comilla
        self.assertFalse(_valid_blind_template("{col} = {hex}"))                    # sin LIKE
        self.assertFalse(_valid_blind_template("LIKE {hex}"))                       # sin {col}


class CraftBlind(unittest.TestCase):
    def test_uses_valid_generated_form(self):
        self.assertEqual(_exec("{col} RLIKE {hex}").craft_blind(), "{col} RLIKE {hex}")

    def test_falls_back_when_unsafe(self):
        # el LLM propone algo que el WAF bloquearía -> respaldo determinista
        self.assertEqual(_exec("SUBSTRING((SELECT {col}),1,1)={hex}").craft_blind(), "{col} LIKE {hex}")


class ExtractBlindDrivesTool(unittest.TestCase):
    def test_extracts_first_row(self):
        row_db = {"user": "admin", "password": "secret42"}

        def oracle(payload: str) -> bool:
            if "1=1" in payload:
                return True
            if "1=2" in payload:
                return False
            m = re.search(r"(\w+) LIKE 0x([0-9a-f]+)", payload, re.IGNORECASE)
            if not m:
                return False
            col, pat = m.group(1), bytes.fromhex(m.group(2)).decode().rstrip("%")
            return col in row_db and row_db[col].startswith(pat)

        row = _exec("{col} LIKE {hex}").extract_blind(
            oracle, "", ("user",), ("password",), "{col} LIKE {hex}")
        self.assertEqual(row, {"username": "admin", "hash": "secret42"})


if __name__ == "__main__":
    unittest.main()
