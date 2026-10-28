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

    def test_sqlmap_wordlists_loaded(self):
        # wordlists reales de sqlmap: miles de nombres, con los de credencial presentes
        cols, tables = knowledge.common_columns(), knowledge.common_tables()
        self.assertGreater(len(cols), 1000)
        self.assertGreater(len(tables), 1000)
        lc = {c.lower() for c in cols}
        self.assertIn("password", lc)
        self.assertIn("username", lc)
        self.assertIn("users", {t.lower() for t in tables})
        # el encabezado de comentario de sqlmap no debe colarse como dato
        self.assertFalse(any(c.startswith("#") for c in cols))

    def test_credential_candidates_prioritized(self):
        user_c, pass_c = knowledge.credential_column_candidates()
        self.assertTrue(user_c and pass_c)
        # las coincidencias exactas van primero -> el caso común se resuelve en pocos sondeos
        self.assertIn("user", [c.lower() for c in user_c[:30]])
        self.assertIn("password", [c.lower() for c in pass_c[:30]])

    def test_credential_candidates_fallback(self):
        # sin wordlist disponible, cae a la lista mínima (no revienta)
        import src.knowledge as k
        orig = k._WORDLISTS
        try:
            k._WORDLISTS = k._WORDLISTS / "no-existe"
            user_c, pass_c = k.credential_column_candidates()
            self.assertIn("user", user_c)
            self.assertIn("password", pass_c)
        finally:
            k._WORDLISTS = orig

    def test_detection_payloads_available(self):
        # payloads de deteccion reales (corpus) o respaldo clasico, nunca vacio
        self.assertTrue(knowledge.detection_payloads())


if __name__ == "__main__":
    unittest.main()
