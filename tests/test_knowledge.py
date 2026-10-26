"""El agente se alimenta de datasets curados: la escalera de evasión y las técnicas de extracción
vienen de archivos JSON, con respaldo determinista. Estas pruebas validan la carga y el uso."""
from __future__ import annotations

import unittest

from src import knowledge
from src.evasion import TRANSFORMS, EvasionEngine, apply_pipeline


class KnowledgeBase(unittest.TestCase):
    def test_bypass_ladder_loads_from_dataset(self):
        ladder = knowledge.bypass_ladder()
        self.assertGreater(len(ladder), 5)
        # cada paso de cada pipeline debe ser un transform que existe en el motor
        for pipeline in ladder:
            for name in pipeline:
                self.assertIn(name, TRANSFORMS)

    def test_engine_uses_dataset_ladder(self):
        # por defecto el motor toma la escalera del dataset (no la constante hardcodeada)
        self.assertEqual(EvasionEngine().ladder, knowledge.bypass_ladder())

    def test_extraction_techniques_present(self):
        techs = knowledge.extraction_techniques()
        for t in ("union", "boolean-blind", "time-based", "error-based"):
            self.assertIn(t, techs)
            self.assertTrue(techs[t])  # no vacío

    def test_fill_template_with_discovered_schema(self):
        out = knowledge.fill("-1{q} UNION SELECT {ucol},{pcol} FROM {table}-- -",
                             q="'", ucol="user", pcol="password", table="users")
        self.assertEqual(out, "-1' UNION SELECT user,password FROM users-- -")

    def test_bypass_payloads_dataset(self):
        bp = knowledge.bypass_payloads()
        self.assertTrue(bp)
        self.assertTrue(all("payload" in e for e in bp))

    def test_real_corpus_loaded(self):
        # corpus real descargado de PayloadsAllTheThings (cientos de payloads, por tecnica)
        c = knowledge.corpus()
        self.assertGreater(knowledge.corpus_size(), 100)
        self.assertIn("union", c)
        self.assertTrue(c["union"])

    def test_corrupt_dataset_falls_back(self):
        # si el archivo no existe, bypass_ladder usa el respaldo determinista (no revienta)
        import src.knowledge as k
        orig = k._DATASETS
        try:
            k._DATASETS = k._DATASETS / "no-existe"
            self.assertEqual(k.bypass_ladder(), k._DEFAULT_LADDER)
        finally:
            k._DATASETS = orig


if __name__ == "__main__":
    unittest.main()
