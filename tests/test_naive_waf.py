"""The naive WAF must block plain SQLi but be bypassable by the evasion grammar — this is what
makes the middle tier demonstrate adaptation. Pure logic (imports the rules, not the server)."""
from __future__ import annotations

import unittest

from src.evasion import apply_pipeline
from waf.rules import is_malicious

PLAIN = "1' UNION SELECT user,password FROM users-- -"
BOOL = "1' AND 1=1-- -"


class NaiveWafRules(unittest.TestCase):
    def test_blocks_plain_union(self) -> None:
        self.assertTrue(is_malicious(PLAIN)[0])

    def test_blocks_plain_boolean(self) -> None:
        self.assertTrue(is_malicious(BOOL)[0])

    def test_case_alone_does_not_bypass(self) -> None:
        # rules are case-insensitive, so mixed case must still be caught
        self.assertTrue(is_malicious(apply_pipeline(PLAIN, ("case",)))[0])

    def test_inline_comment_bypasses_union(self) -> None:
        # `/**/` between keywords breaks the \s+ signatures -> the agent can get through
        self.assertFalse(is_malicious(apply_pipeline(PLAIN, ("inline_comment",)))[0])

    def test_union_all_bypasses(self) -> None:
        # "UNION ALL SELECT" no longer matches `union\s+select`
        self.assertFalse(is_malicious(apply_pipeline(PLAIN, ("union_all",)))[0])

    def test_benign_traffic_passes(self) -> None:
        self.assertFalse(is_malicious("id=1&Submit=Submit")[0])
        self.assertFalse(is_malicious("username=admin&password=password&Login=Login")[0])

    def test_some_ladder_rung_bypasses(self) -> None:
        # the engine's escalation ladder must contain at least one surface the naive WAF lets through
        from src.evasion import LADDER
        self.assertTrue(any(not is_malicious(apply_pipeline(PLAIN, p))[0] for p in LADDER))


if __name__ == "__main__":
    unittest.main()
