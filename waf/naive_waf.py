"""Naive WAF: a tiny reverse proxy that blocks requests matching a documented regex blacklist
(see rules.py) and forwards everything else to the DVWA backend. It is the bypassable middle tier
between "no WAF" and "ModSecurity + OWASP CRS".

Run (inside the container): BACKEND=http://dvwa:80 PORT=8082 python naive_waf.py
It inspects the URL-decoded query string and request body so it covers GET (low) and POST
(medium/high) alike."""
from __future__ import annotations

import os
import urllib.parse

import requests
from flask import Flask, Response, request

from rules import is_malicious  # same directory inside the container image

BACKEND = os.getenv("BACKEND", "http://dvwa:80").rstrip("/")
PORT = int(os.getenv("PORT", "8082"))

# Headers we must not copy verbatim when relaying the response.
_HOP_BY_HOP = {"content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding"}

app = Flask(__name__)


@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
def proxy(path: str) -> Response:
    decoded_query = urllib.parse.unquote_plus(request.query_string.decode("utf-8", "ignore"))
    decoded_body = urllib.parse.unquote_plus(request.get_data(as_text=True) or "")
    blocked, rule = is_malicious(decoded_query + "\n" + decoded_body)
    if blocked:
        return Response(f"Blocked by Naive-WAF (rule: {rule})", status=403, mimetype="text/plain")

    upstream = requests.request(
        method=request.method,
        url=f"{BACKEND}/{path}",
        params=request.args.to_dict(flat=False),
        data=request.get_data(),
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        cookies=request.cookies,
        allow_redirects=False,  # let the client follow DVWA's login/redirect flow
        timeout=30,
    )
    # Relay status + headers (preserving duplicate Set-Cookie via the raw urllib3 headers).
    headers = [(k, v) for k, v in upstream.raw.headers.items() if k.lower() not in _HOP_BY_HOP]
    return Response(upstream.content, status=upstream.status_code, headers=headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
