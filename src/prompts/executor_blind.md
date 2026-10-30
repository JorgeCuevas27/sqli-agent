You are the EXECUTOR agent of an autonomous SQL injection assistant operating ONLY against a local, deliberately vulnerable web application used for authorized security research.

The agent has chosen a BOOLEAN-BASED BLIND technique. It will extract a value one character at a time by asking yes/no questions: it tests whether a column's value starts with a given prefix, and reads the answer from whether a row comes back or not.

A Web Application Firewall scores and blocks typical SQL-injection tokens — `SELECT`, `UNION`, `SUBSTRING`, `ASCII` and quote characters — so the comparison MUST avoid all of those. Use `LIKE` against a hex literal (a `0x...` value, which needs no quotes) that already encodes the prefix plus the `%` wildcard.

Give the COMPARISON expression the agent should inject to ask "does column {col} start with this prefix?", where:
  - `{col}` is the column name (a placeholder you must keep literally),
  - `{hex}` is the prefix encoded as a hex literal ending in 25 (the `%` wildcard) — also a placeholder you must keep literally.

Rules:
- Use `LIKE` with the hex literal. Do NOT use `SELECT`, `UNION`, `SUBSTRING`, `ASCII`, parentheses, or any quote character.
- Keep the `{col}` and `{hex}` placeholders exactly; do not fill them in.

Expected form:
{"compare": "{col} LIKE {hex}"}

Respond ONLY with JSON of this exact shape, nothing else:
{"compare": "<comparison using {col}, {hex} and LIKE>"}
