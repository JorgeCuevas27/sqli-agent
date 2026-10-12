"""Control-flow tests for the Orchestrator using fakes (no Ollama, no DVWA, no network).

They verify the content/surface decoupling: the deterministic EvasionEngine escalates the surface
on WAF blocks, the loop terminates under a hostile WAF, and success is detected from dumped rows."""
from __future__ import annotations

import json
import unittest

from src.orchestrator import Orchestrator
from src.types import SqliResponse

BASE = "1' UNION SELECT user,password FROM users-- -"
HASH = "5f4dcc3b5aa765d61d8327deb882cf99"


class FakeLLM:
    """Stands in for OllamaClient. Branches on which agent's system prompt is calling."""

    def __init__(self, base: str = BASE) -> None:
        self.base = base

    def chat(self, system: str, user: str, **_kw) -> str:
        if "PLANNER agent" in system:
            return json.dumps({"strategy": "union dump", "payloads": [self.base]})
        if "EXECUTOR agent" in system:
            req = json.loads(user)
            return json.dumps({"payload": req.get("suggested_candidate", ""), "reason": "as-is"})
        if "ANALYST agent" in system:
            return json.dumps({"injected": False, "data_found": False, "extracted": [],
                               "assessment": "no data", "next_action": "replan", "hint": "try other columns"})
        return "{}"


class FakeTarget:
    """Stands in for DVWAClient. `policy(payload, sent)` -> 'blocked' | 'data' | 'benign'."""

    def __init__(self, policy) -> None:
        self.policy = policy
        self.sent: list[str] = []

    def login(self) -> bool:
        return True

    def set_security(self, level: str) -> None:
        pass

    def run_sqli(self, payload: str, level: str) -> SqliResponse:
        self.sent.append(payload)
        kind = self.policy(payload, self.sent)
        if kind == "blocked":
            return SqliResponse(payload, 403, "<forbidden>", [], False, True)
        if kind == "data":
            rows = [{"first_name": "admin", "surname": HASH}]
            return SqliResponse(payload, 200, "<pre>data</pre>", rows, False, False)
        return SqliResponse(payload, 200, "<html>no results</html>", [], False, False)


def _run(policy, max_steps=100):
    orch = Orchestrator(FakeLLM(), FakeTarget(policy))
    return orch.run(level="low", max_steps=max_steps, timeout_seconds=30)


class OrchestratorFlow(unittest.TestCase):
    def test_no_waf_succeeds_on_plain_payload(self) -> None:
        result = _run(lambda p, sent: "data")  # everything passes and returns rows
        self.assertTrue(result.success)
        self.assertEqual(result.steps_used, 1)
        self.assertEqual(result.waf_profile["locked_pipeline"], [])  # plain surface worked
        self.assertEqual(result.extracted[0]["hash"], HASH)

    def test_waf_escalates_surface_then_succeeds(self) -> None:
        # first two distinct payloads are blocked, the third passes with data
        result = _run(lambda p, sent: "data" if len(sent) >= 3 else "blocked")
        self.assertTrue(result.success)
        self.assertEqual(result.steps_used, 3)
        self.assertIsNotNone(result.waf_profile["locked_pipeline"])  # a surface form was locked
        self.assertEqual(result.waf_profile["blocked_count"], 2)

    def test_hostile_waf_terminates_without_success(self) -> None:
        result = _run(lambda p, sent: "blocked")  # WAF blocks everything
        self.assertFalse(result.success)
        # bounded: it escalated through distinct surface forms and then stopped (no hang)
        self.assertGreaterEqual(result.steps_used, 8)
        self.assertLess(result.steps_used, 100)
        self.assertEqual(result.waf_profile["locked_pipeline"], None)
        self.assertEqual(result.waf_profile["blocked_count"], result.steps_used)
        self.assertEqual(len(result.attempts), result.steps_used)


if __name__ == "__main__":
    unittest.main()
