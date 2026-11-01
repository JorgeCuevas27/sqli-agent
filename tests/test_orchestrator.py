from __future__ import annotations

import json
import re
import unittest

from src.orchestrator import Orchestrator
from src.types import SqliResponse


class FakeLLM:

    def chat(self, system: str, user: str, **_kw) -> str:
        if "PLANNER agent" in system:
            return json.dumps({"strategy": "UNION-based discovery against a MySQL target"})
        if "EXECUTOR agent" in system:
            return json.dumps({"payload": ""})
        if "ANALYST agent" in system:
            return json.dumps({"username_column": "user", "password_column": "password"})
        return "{}"


class FakeTarget:

    def __init__(self, schema, creds, orig_columns=2):
        self.schema = schema
        self.creds = creds
        self.orig_columns = orig_columns

    def login(self):
        return True

    def set_security(self, level):
        pass

    def _resp(self, payload, rows=None, db_error=False):
        return SqliResponse(payload, 200, "<pre></pre>", rows or [], db_error, False)

    def run_sqli(self, payload: str, level: str) -> SqliResponse:
        p = payload.strip()
        if p == "1":
            return self._resp(payload, [{"first_name": "admin", "surname": "admin"}])
        if p == "1'":
            return self._resp(payload, db_error=True)
        if "AND 1=1" in payload:
            return self._resp(payload, [{"first_name": "admin", "surname": "admin"}])
        if "AND 1=2" in payload:
            return self._resp(payload)
        if "@@version" in payload:
            return self._resp(payload, [{"first_name": "10.5.19-MariaDB", "surname": "2"}])
        m = re.search(r"ORDER BY (\d+)", payload, re.IGNORECASE)
        if m:
            return self._resp(payload, db_error=int(m.group(1)) > self.orig_columns)
        if "information_schema.tables" in payload:
            return self._resp(payload, [{"first_name": t, "surname": "2"} for t in self.schema])
        if "information_schema.columns" in payload:
            hx = re.search(r"table_name=0x([0-9a-f]+)", payload, re.IGNORECASE)
            table = bytes.fromhex(hx.group(1)).decode() if hx else ""
            return self._resp(payload, [{"first_name": c, "surname": "2"} for c in self.schema.get(table, [])])
        if "UNION SELECT" in payload and "1000" in payload and "FROM" not in payload:
            sents = re.findall(r"\b1\d{3}\b", payload)
            if len(sents) == self.orig_columns:
                return self._resp(payload, [{"first_name": sents[0], "surname": sents[1]}])
            return self._resp(payload)
        for table, rows in self.creds.items():
            if f"FROM {table}" in payload:
                return self._resp(payload, [{"first_name": u, "surname": p} for u, p in rows])
        return self._resp(payload)


def _run(target):
    return Orchestrator(FakeLLM(), target).run(level="low", max_steps=100, timeout_seconds=30)


class DiscoversDVWASchema(unittest.TestCase):
    def test_discovers_and_dumps(self):
        target = FakeTarget(
            schema={
                "users": ["user_id", "first_name", "last_name", "user", "password", "avatar"],
                "guestbook": ["comment_id", "comment", "name"],
            },
            creds={"users": [("admin", "5f4dcc3b5aa765d61d8327deb882cf99"),
                             ("gordonb", "e99a18c428cb38d5f260853678922e03")]},
        )
        result = _run(target)
        self.assertTrue(result.success)
        self.assertEqual(result.extracted[0]["username"], "admin")
        self.assertEqual(len(result.extracted), 2)
        self.assertTrue(result.payloads)
        self.assertTrue(all({"payload", "blocked", "http_status"} <= e.keys() for e in result.payloads))
        self.assertTrue(any("tablas=" in line for line in result.trace))
        trace = "\n".join(result.trace)
        self.assertIn("boolean-based", trace)
        self.assertIn("MariaDB", trace)
        self.assertIn("verificada=True", trace)


class CredentialCandidatesFromLLM(unittest.TestCase):

    class _GuessLLM:
        def __init__(self, payload):
            self.payload = payload

        def chat(self, system, user, **_kw):
            if "username_columns" in system:
                return self.payload
            return "{}"

    def _orch(self, payload):
        return Orchestrator(self._GuessLLM(payload), FakeTarget({}, {}))

    def test_llm_names_grounded_in_sqlmap(self):
        o = self._orch(json.dumps({"username_columns": ["user", "zzz_fake_col"],
                                    "password_columns": ["password", "qqq_fake"]}))
        users, passwords = o._credential_candidates(lambda _m: None)
        self.assertEqual(users[0], "user")
        self.assertEqual(passwords[0], "password")
        self.assertLess(users.index("user"), users.index("zzz_fake_col"))

    def test_fallback_when_llm_empty(self):
        o = self._orch("{}")
        users, passwords = o._credential_candidates(lambda _m: None)
        self.assertTrue(users and passwords)


class DiscoversDifferentSchema(unittest.TestCase):

    def test_finds_nonobvious_credentials(self):
        target = FakeTarget(
            schema={"news": ["id", "title", "body"], "accounts": ["id", "uname", "secret"]},
            creds={"accounts": [("root", "deadbeefcafebabe")]},
        )
        result = _run(target)
        self.assertTrue(result.success)
        self.assertEqual(result.extracted[0]["username"], "root")
        self.assertEqual(result.extracted[0]["hash"], "deadbeefcafebabe")


if __name__ == "__main__":
    unittest.main()
