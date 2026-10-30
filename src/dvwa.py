"""DVWA client — the deterministic tool the Executor drives.

Targets ONLY a local DVWA instance (a deliberately vulnerable app used for research).
Handles the per-level mechanics of the SQL Injection page so the agents can reason about
payloads without caring how the request is shaped."""
from __future__ import annotations

import time
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .config import CONFIG
from .types import SqliResponse

_RETRIES = 4          # un timeout/hiccup puntual del WAF no debe tumbar la corrida
_TIMEOUT = 20         # segundos por intento

_SQL_ERROR_MARKERS = (
    "error in your sql syntax",
    "you have an error in your sql",
    "sql syntax",
    "warning: mysqli",
    "unknown column",
    "in 'order clause'",
    "different number of columns",
    "fetch_array()",
    "mysqli_fetch",
    "supplied argument is not a valid mysql",
    "sqlstate",
)

# When DVWA sits behind a WAF (ModSecurity or NAXSI) a blocked request never reaches the
# database: the proxy answers with one of these statuses, often with a recognisable body.
_BLOCK_STATUS = (403, 406, 501)
_WAF_MARKERS = ("mod_security", "modsecurity", "not acceptable", "access denied")


class DVWAClient:
    def __init__(
        self,
        base_url: str = CONFIG.dvwa_url,
        user: str = CONFIG.dvwa_user,
        password: str = CONFIG.dvwa_password,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.session = requests.Session()

    def _send(self, method: str, url: str, **kwargs) -> requests.Response:
        """Hace la petición con reintentos: ante un timeout/corte de red transitorio (típico del
        contenedor WAF bajo muchas peticiones de la extracción ciega) reintenta en vez de reventar."""
        kwargs.setdefault("timeout", _TIMEOUT)
        last: Exception | None = None
        for attempt in range(_RETRIES):
            try:
                return self.session.request(method, url, **kwargs)
            except requests.exceptions.RequestException as exc:
                last = exc
                time.sleep(0.4 * (attempt + 1))
        raise RuntimeError(f"sin respuesta de {url} tras {_RETRIES} intentos ({last})")

    def _user_token(self, path: str) -> str:
        html = self._send("GET", f"{self.base}{path}").text
        field = BeautifulSoup(html, "html.parser").find("input", {"name": "user_token"})
        return field["value"] if field else ""

    def login(self) -> bool:
        token = self._user_token("/login.php")
        resp = self._send(
            "POST",
            f"{self.base}/login.php",
            data={
                "username": self.user,
                "password": self.password,
                "Login": "Login",
                "user_token": token,
            },
            allow_redirects=True,
        )
        # DVWA redirects to index.php on success and back to login.php on failure.
        return "login.php" not in resp.url

    def set_security(self, level: str) -> None:
        token = self._user_token("/security.php")
        self._send(
            "POST",
            f"{self.base}/security.php",
            data={"security": level, "seclev_submit": "Submit", "user_token": token},
        )
        host = urlparse(self.base).hostname or "localhost"
        self.session.cookies.set("security", level, domain=host)

    def run_sqli(self, payload: str, level: str) -> SqliResponse:
        level = level.lower()
        path = "/vulnerabilities/sqli/"
        blocked_before = False
        if level == "high":
            # The id is read from a session variable set on a separate page, then shown on GET.
            post = self._send(
                "POST",
                f"{self.base}{path}session-input.php",
                data={"id": payload, "Submit": "Submit"},
            )
            blocked_before = self._is_blocked(post)
            resp = self._send("GET", f"{self.base}{path}")
        elif level == "medium":
            resp = self._send(
                "POST", f"{self.base}{path}", data={"id": payload, "Submit": "Submit"}
            )
        else:  # low
            resp = self._send(
                "GET", f"{self.base}{path}", params={"id": payload, "Submit": "Submit"}
            )
        result = self._parse(payload, resp)
        if blocked_before:  # the WAF stopped the session-input POST that carries the payload
            result.blocked = True
        return result

    @staticmethod
    def _is_blocked(resp: requests.Response) -> bool:
        if resp.status_code in _BLOCK_STATUS:
            return True
        low = resp.text.lower()
        return any(marker in low for marker in _WAF_MARKERS)

    @staticmethod
    def _parse(payload: str, resp: requests.Response) -> SqliResponse:
        html = resp.text
        low = html.lower()
        db_error = any(marker in low for marker in _SQL_ERROR_MARKERS)
        blocked = resp.status_code in _BLOCK_STATUS or any(m in low for m in _WAF_MARKERS)

        rows: list[dict[str, str]] = []
        for pre in BeautifulSoup(html, "html.parser").find_all("pre"):
            text = pre.get_text("\n")
            entry: dict[str, str] = {}
            for line in text.splitlines():
                line = line.strip()
                lower = line.lower()
                if lower.startswith("id:"):
                    entry["id"] = line.split(":", 1)[1].strip()
                elif lower.startswith("first name:"):
                    entry["first_name"] = line.split(":", 1)[1].strip()
                elif lower.startswith("surname:"):
                    entry["surname"] = line.split(":", 1)[1].strip()
            if "first_name" in entry or "surname" in entry:
                rows.append(entry)

        return SqliResponse(
            payload=payload,
            http_status=resp.status_code,
            raw_html=html,
            rows=rows,
            db_error=db_error,
            blocked=blocked,
        )
