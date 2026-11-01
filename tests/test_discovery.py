from __future__ import annotations

import re
import unittest

from src.discovery import ProbeResult, SchemaDiscovery


class FakeDB:

    def __init__(self, schema, creds, quote="'", orig_columns=2):
        self.schema = schema
        self.creds = creds
        self.quote = quote
        self.orig_columns = orig_columns

    def probe(self, sql: str) -> ProbeResult:
        if sql == f"1{self.quote}":
            return ProbeResult(db_error=True)
        m = re.search(r"ORDER BY (\d+)", sql, re.IGNORECASE)
        if m:
            return ProbeResult(db_error=int(m.group(1)) > self.orig_columns)
        if "information_schema.tables" in sql:
            return ProbeResult(cells=[[t, "2"] for t in self.schema])
        if "information_schema.columns" in sql:
            hx = re.search(r"table_name=0x([0-9a-f]+)", sql, re.IGNORECASE)
            table = bytes.fromhex(hx.group(1)).decode() if hx else ""
            return ProbeResult(cells=[[c, "2"] for c in self.schema.get(table, [])])
        if "UNION SELECT" in sql and "1000" in sql and "FROM" not in sql:
            sents = re.findall(r"\b1\d{3}\b", sql)
            if len(sents) == self.orig_columns:
                return ProbeResult(cells=[[sents[0], sents[1]]])
            return ProbeResult()
        for table, rows in self.creds.items():
            if f"FROM {table}" in sql:
                return ProbeResult(cells=[[u, p] for u, p in rows])
        return ProbeResult()


class DiscoveryOnDVWALikeSchema(unittest.TestCase):
    def setUp(self):
        self.db = FakeDB(
            schema={
                "users": ["user_id", "first_name", "last_name", "user", "password", "avatar"],
                "guestbook": ["comment_id", "comment", "name"],
            },
            creds={"users": [("admin", "5f4dcc3b5aa765d61d8327deb882cf99"),
                             ("gordonb", "e99a18c428cb38d5f260853678922e03")]},
        )

    def test_discovers_schema_and_dumps(self):
        res = SchemaDiscovery(self.db.probe).run()
        self.assertTrue(res.injectable)
        self.assertEqual(res.quote, "'")
        self.assertEqual(res.columns, 2)
        self.assertEqual(res.reflected, [1, 2])
        self.assertIn("users", res.tables)
        self.assertEqual(res.target_table, "users")
        self.assertEqual(res.cred_columns, ("user", "password"))
        self.assertEqual(len(res.extracted), 2)
        self.assertEqual(res.extracted[0]["username"], "admin")


class DiscoveryOnDifferentSchema(unittest.TestCase):

    def setUp(self):
        self.db = FakeDB(
            schema={
                "news": ["id", "title", "body"],
                "accounts": ["id", "uname", "secret"],
            },
            creds={"accounts": [("root", "deadbeefcafebabe")]},
        )

    def test_finds_nonobvious_table_and_columns(self):
        res = SchemaDiscovery(self.db.probe).run()
        self.assertEqual(res.target_table, "accounts")
        self.assertEqual(res.cred_columns, ("uname", "secret"))
        self.assertEqual(res.extracted[0]["username"], "root")
        self.assertEqual(res.extracted[0]["hash"], "deadbeefcafebabe")


if __name__ == "__main__":
    unittest.main()
