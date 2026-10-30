"""El reconocimiento elige la técnica por OBSERVACIÓN (árbol OWASP WSTG), no por el nombre del WAF.
Un probe falso simula cada caso (refleja / solo booleano / todo bloqueado / solo retardo)."""
from __future__ import annotations

import unittest

from src.discovery import ProbeResult
from src.recon import TechniqueSelector


class TechniqueSelection(unittest.TestCase):
    def test_union_when_reflects(self):
        def probe(sql):
            if "UNION SELECT" in sql:
                return ProbeResult(cells=[["1000", "1001"]])   # el UNION pasa y refleja
            if "AND 1=1" in sql:
                return ProbeResult(cells=[["a", "b"]])
            if "AND 1=2" in sql:
                return ProbeResult()
            if sql == "1'":
                return ProbeResult(db_error=True)
            return ProbeResult()
        r = TechniqueSelector(probe).select()
        self.assertTrue(r.signals["union"])
        self.assertEqual(r.technique, "union")

    def test_boolean_when_union_blocked(self):
        def probe(sql):
            if "UNION SELECT" in sql:
                return ProbeResult(blocked=True)               # WAF bloquea UNION
            if "AND 1=1" in sql:
                return ProbeResult(cells=[["a", "b"]])
            if "AND 1=2" in sql:
                return ProbeResult()
            if sql == "1'":
                return ProbeResult(blocked=True)               # comilla bloqueada (no error visible)
            return ProbeResult()
        r = TechniqueSelector(probe).select()
        self.assertFalse(r.signals["union"])
        self.assertTrue(r.signals["boolean"])
        self.assertEqual(r.technique, "boolean")

    def test_none_when_all_blocked(self):
        r = TechniqueSelector(lambda sql: ProbeResult(blocked=True)).select()
        self.assertEqual(r.technique, "none")
        self.assertFalse(r.injectable)

    def test_detects_time_based(self):
        probe = lambda sql: ProbeResult(blocked=True)          # nada observable por UNION/boolean/error
        time_probe = lambda sql: 2.0 if "SLEEP" in sql else 0.0
        r = TechniqueSelector(probe, time_probe).select()
        self.assertTrue(r.signals["time"])                     # se DETECTA el time-based
        self.assertTrue(r.injectable)
        self.assertEqual(r.technique, "none")                  # detectada, pero sin extractor -> no atacable

    def test_detects_error_based(self):
        def probe(sql):
            if sql == "1'":
                return ProbeResult(db_error=True)              # error visible
            return ProbeResult(blocked=True)
        r = TechniqueSelector(probe).select()
        self.assertTrue(r.signals["error"])


if __name__ == "__main__":
    unittest.main()
