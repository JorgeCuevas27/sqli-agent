from __future__ import annotations

import unittest

from src.dvwa import DVWAClient


class _FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text


def _client(html: str) -> DVWAClient:
    c = DVWAClient(base_url="http://x")
    c._send = lambda method, url, **kw: _FakeResp(html)
    return c


class DetectInjectionPoint(unittest.TestCase):
    def test_detects_get_form(self):
        html = '<form method="GET"><input name="id"><input type="submit" name="Submit"></form>'
        info = _client(html).detect_injection_point("low")
        self.assertEqual(info["method"], "GET")
        self.assertEqual(info["param"], "id")

    def test_detects_post_form(self):
        html = '<form method="post"><select name="id"></select><input name="Submit"></form>'
        info = _client(html).detect_injection_point("medium")
        self.assertEqual(info["method"], "POST")
        self.assertEqual(info["param"], "id")

    def test_detects_session_based(self):
        info = _client('<a href="session-input.php">change your id</a>').detect_injection_point("high")
        self.assertEqual(info["method"], "SESSION")


if __name__ == "__main__":
    unittest.main()
