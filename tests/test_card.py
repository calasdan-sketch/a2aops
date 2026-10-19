"""Tests for AgentCard fetch, validate, and lint."""

import http.server
import json
import threading
import unittest
from pathlib import Path

from a2aops.card import (CardFetchError, check_card, fetch_card,
                         format_diagnostics, has_errors, lint_card,
                         validate_card)

FIX = Path(__file__).with_name("fixtures")


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class CardServer:
    """Tiny fixture server exposing both well-known paths."""

    def __init__(self, routes):
        self.routes = routes  # path -> (status, body)

        routes_ref = routes

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                status, body = routes_ref.get(self.path, (404, b"nope"))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._srv.server_address[1]
        self._t = threading.Thread(target=self._srv.serve_forever,
                                   kwargs={"poll_interval": 0.05}, daemon=True)
        self._t.start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self._srv.shutdown()
        self._srv.server_close()
        self._t.join(timeout=5)


class TestFetch(unittest.TestCase):
    def test_fetch_modern_path(self):
        body = json.dumps(load("card_v1_minimal.json")).encode()
        srv = CardServer({"/.well-known/agent-card.json": (200, body)})
        try:
            card, info = fetch_card(srv.base)
            self.assertEqual(card["name"], "Minimal Agent")
            self.assertFalse(info.legacy_fallback)
            self.assertEqual(info.path_used, "/.well-known/agent-card.json")
            self.assertEqual(info.status, 200)
        finally:
            srv.stop()

    def test_fetch_legacy_fallback(self):
        body = json.dumps(load("card_v03.json")).encode()
        srv = CardServer({"/.well-known/agent.json": (200, body)})
        try:
            card, info = fetch_card(srv.base)
            self.assertEqual(card["name"], "Legacy Agent")
            self.assertTrue(info.legacy_fallback)
        finally:
            srv.stop()

    def test_fetch_neither_path(self):
        srv = CardServer({})
        try:
            with self.assertRaises(CardFetchError):
                fetch_card(srv.base)
        finally:
            srv.stop()

    def test_fetch_non_json(self):
        srv = CardServer({"/.well-known/agent-card.json": (200, b"<html>nope")})
        try:
            with self.assertRaises(CardFetchError):
                fetch_card(srv.base)
        finally:
            srv.stop()

    def test_fetch_connection_refused(self):
        with self.assertRaises(CardFetchError):
            fetch_card("http://127.0.0.1:1", timeout=1)

    def test_fetch_bom_tolerated(self):
        body = b"\xef\xbb\xbf" + json.dumps(load("card_v1_minimal.json")).encode()
        srv = CardServer({"/.well-known/agent-card.json": (200, body)})
        try:
            card, _ = fetch_card(srv.base)
            self.assertEqual(card["name"], "Minimal Agent")
        finally:
            srv.stop()


class TestValidate(unittest.TestCase):
    def test_valid_card_has_no_errors(self):
        diags = validate_card(load("card_v1_valid.json"))
        self.assertFalse(has_errors(diags), format_diagnostics(diags))

    def test_minimal_valid_card(self):
        diags = validate_card(load("card_v1_minimal.json"))
        self.assertFalse(has_errors(diags), format_diagnostics(diags))

    def test_unusual_but_valid_card_has_no_errors(self):
        """D2: extensions, extra fields, gRPC-only, localhost HTTP must not error."""
        card = load("card_v1_unusual_valid.json")
        diags = validate_card(card)
        self.assertFalse(has_errors(diags), format_diagnostics(diags))

    def test_broken_card_errors(self):
        diags = validate_card(load("card_broken.json"))
        codes = [d.code for d in diags if d.severity == "error"]
        for expected in ("E101", "E104", "E105", "E106", "E107", "E108",
                         "E110", "E111", "E113"):
            self.assertIn(expected, codes, f"missing {expected}: {format_diagnostics(diags)}")

    def test_non_object_card(self):
        diags = validate_card([1, 2, 3])
        self.assertTrue(has_errors(diags))
        self.assertEqual(diags[0].code, "E001")

    def test_v03_card_fails_v1_validation(self):
        diags = validate_card(load("card_v03.json"))
        self.assertTrue(has_errors(diags))
        self.assertTrue(any("supportedInterfaces" in d.message for d in diags))


class TestLint(unittest.TestCase):
    def test_lint_never_errors(self):
        for name in ("card_v1_valid.json", "card_v1_minimal.json",
                     "card_v1_unusual_valid.json", "card_v03.json",
                     "card_broken.json", "card_drifted_auth.json"):
            for d in lint_card(load(name)):
                self.assertNotEqual(d.severity, "error", f"{name}: {d}")

    def test_plain_http_warns_but_loopback_does_not(self):
        card = load("card_v1_valid.json")
        card["supportedInterfaces"][0]["url"] = "http://hotels.example.com/a2a/v1"
        codes = [d.code for d in lint_card(card)]
        self.assertIn("W201", codes)

        unusual = load("card_v1_unusual_valid.json")  # localhost http
        codes = [d.code for d in lint_card(unusual)]
        self.assertNotIn("W201", codes)

    def test_unreferenced_scheme_warns(self):
        codes = [d.code for d in lint_card(load("card_drifted_auth.json"))]
        self.assertIn("W202", codes)

    def test_streaming_without_push_is_info(self):
        diags = lint_card(load("card_v1_unusual_valid.json"))
        i205 = [d for d in diags if d.code == "I205"]
        self.assertEqual(len(i205), 1)
        self.assertEqual(i205[0].severity, "info")


if __name__ == "__main__":
    unittest.main()
