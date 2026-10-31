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
        self._injection: dict | None = None   # punto de inyección detectado (parámetro + método)

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

    def detect_injection_point(self, level: str) -> dict:
        """RECONOCE el punto de inyección leyendo el formulario de la propia página (el parámetro y
        el método HTTP), en vez de asumirlos. Así el método no está codificado por nivel: se lee del
        atributo `method` del <form> y el parámetro del nombre del campo. El resultado se cachea."""
        path = "/vulnerabilities/sqli/"
        info = {"param": "id", "method": "GET", "fields": ["id"]}
        try:
            html = self._send("GET", f"{self.base}{path}").text
            form = BeautifulSoup(html, "html.parser").find("form")
            fields = []
            method = "GET"
            if form:
                method = (form.get("method") or "GET").strip().upper()
                for tag in form.find_all(["input", "select", "textarea"]):
                    name = tag.get("name")
                    if name and name.lower() != "submit":
                        fields.append(name)
            if fields:
                info = {"param": fields[0], "method": method, "fields": fields}
            elif "session-input" in html:   # DVWA high: el id se envía en una página aparte
                info = {"param": "id", "method": "SESSION", "fields": ["id"]}
        except Exception:
            pass
        self._injection = info
        return info

    def run_sqli(self, payload: str, level: str) -> SqliResponse:
        info = self._injection or self.detect_injection_point(level)
        param, method = info["param"], info["method"]
        path = "/vulnerabilities/sqli/"
        blocked_before = False
        if method == "SESSION":
            # El id se lee de una variable de sesión fijada en otra página, y se muestra por GET.
            post = self._send(
                "POST",
                f"{self.base}{path}session-input.php",
                data={param: payload, "Submit": "Submit"},
            )
            blocked_before = self._is_blocked(post)
            resp = self._send("GET", f"{self.base}{path}")
        elif method == "POST":
            resp = self._send(
                "POST", f"{self.base}{path}", data={param: payload, "Submit": "Submit"}
            )
        else:  # GET
            resp = self._send(
                "GET", f"{self.base}{path}", params={param: payload, "Submit": "Submit"}
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
