"""Extracción boolean-blind (LIKE) — la técnica que vence a NAXSI. Probada con un oráculo falso
que simula una fila usuario/contraseña, respondiendo a los LIKE como lo haría la base de datos."""
from __future__ import annotations

import re
import unittest

from src.blind import BlindExtractor

ROW = {"user": "admin", "password": "secret42"}


def fake_oracle(payload: str) -> bool:
    if "1=1" in payload:
        return True
    if "1=2" in payload:
        return False
    m = re.search(r"(\w+) LIKE 0x([0-9a-f]+)", payload, re.IGNORECASE)
    if not m:
        return False
    col = m.group(1)
    pattern = bytes.fromhex(m.group(2)).decode().rstrip("%")
    return col in ROW and ROW[col].startswith(pattern)


class BlindExtraction(unittest.TestCase):
    def test_confirm(self):
        self.assertTrue(BlindExtractor(fake_oracle, quote="").confirm())

    def test_find_column(self):
        bx = BlindExtractor(fake_oracle, quote="")
        self.assertEqual(bx.find_column(("password", "pass")), "password")
        self.assertEqual(bx.find_column(("nope", "nada")), "")

    def test_extract_char_by_char(self):
        bx = BlindExtractor(fake_oracle, quote="")
        self.assertEqual(bx.extract("password", charset="0123456789abcdefghijklmnopqrstuvwxyz"), "secret42")

    def test_dump_first_row(self):
        row = BlindExtractor(fake_oracle, quote="").dump_first_row()
        self.assertEqual(row, {"username": "admin", "hash": "secret42"})


if __name__ == "__main__":
    unittest.main()
