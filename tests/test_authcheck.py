"""Tests for the read-only auth-surface check."""

import json
import unittest
from pathlib import Path
from unittest import mock

from a2aops import authcheck
from a2aops.card import has_errors

FIX = Path(__file__).with_name("fixtures")


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


OIDC_DOC = {
    "issuer": "https://login.example.com",
    "token_endpoint": "https://login.example.com/oauth/token",
    "authorization_endpoint": "https://login.example.com/authorize",
}


class TestAuthSurface(unittest.TestCase):
    def test_consistent_card_is_clean(self):
        card = load("card_v1_valid.json")
        with mock.patch.object(authcheck, "_fetch_json", return_value=(dict(OIDC_DOC), None)):
            diags = authcheck.check_auth_surface(card)
        self.assertFalse(has_errors(diags), [str(d) for d in diags])

    def test_undeclared_requirement_is_error(self):
        card = load("card_drifted_auth.json")
        with mock.patch.object(authcheck, "_fetch_json", return_value=(None, "DNS failure")):
            diags = authcheck.check_auth_surface(card)
        codes = [d.code for d in diags]
        self.assertIn("E341", codes)  # ghost-scheme
        self.assertIn("E303", codes)  # unreachable OIDC discovery
        self.assertTrue(has_errors(diags))

    def test_oidc_without_token_endpoint_is_drift(self):
        card = load("card_v1_valid.json")
        doc = {"issuer": "https://login.example.com"}  # no token_endpoint
        with mock.patch.object(authcheck, "_fetch_json", return_value=(doc, None)):
            diags = authcheck.check_auth_surface(card)
        self.assertTrue(any(d.code == "E305" for d in diags))

    def test_issuer_mismatch_warns(self):
        card = load("card_v1_valid.json")
        doc = dict(OIDC_DOC, issuer="https://evil.example.net")
        with mock.patch.object(authcheck, "_fetch_json", return_value=(doc, None)):
            diags = authcheck.check_auth_surface(card)
        self.assertTrue(any(d.code == "W306" for d in diags))

    def test_oauth2_flow_without_token_url(self):
        card = load("card_v1_minimal.json")
        card["securitySchemes"] = {"sso": {"oauth2SecurityScheme": {
            "flows": {"authorizationCode": {"authorizationUrl": "https://x.example/a"}}}}}
        diags = authcheck.check_auth_surface(card)
        self.assertTrue(any(d.code == "E313" for d in diags))

    def test_oauth2_empty_flows(self):
        card = load("card_v1_minimal.json")
        card["securitySchemes"] = {"sso": {"oauth2SecurityScheme": {"flows": {}}}}
        diags = authcheck.check_auth_surface(card)
        self.assertTrue(any(d.code == "E311" for d in diags))

    def test_apikey_missing_fields(self):
        card = load("card_v1_minimal.json")
        card["securitySchemes"] = {"k": {"apiKeySecurityScheme": {"name": "X-Key"}}}
        diags = authcheck.check_auth_surface(card)
        self.assertTrue(any(d.code == "E331" for d in diags))

    def test_bearer_without_format_is_info_only(self):
        card = load("card_v1_minimal.json")
        card["securitySchemes"] = {"b": {"httpAuthSecurityScheme": {"scheme": "bearer"}}}
        diags = authcheck.check_auth_surface(card)
        infos = [d for d in diags if d.code == "I321"]
        self.assertEqual(len(infos), 1)
        self.assertFalse(has_errors(diags))

    def test_unknown_scheme_shape_warns_not_errors(self):
        """D2 leniency: unrecognized shapes never fail the check."""
        card = load("card_v1_minimal.json")
        card["securitySchemes"] = {"weird": {"quantumAuthScheme": {"qubits": 5}}}
        diags = authcheck.check_auth_surface(card)
        self.assertTrue(any(d.code == "W343" for d in diags))
        self.assertFalse(has_errors(diags))

    def test_offline_mode_skips_remote_fetch(self):
        card = load("card_v1_valid.json")
        with mock.patch.object(authcheck, "_fetch_json",
                               side_effect=AssertionError("must not fetch")):
            diags = authcheck.check_auth_surface(card, check_remote=False)
        self.assertFalse(has_errors(diags), [str(d) for d in diags])

    def test_never_requests_credentials(self):
        """The module must not contain token-requesting code paths."""
        import inspect
        src = inspect.getsource(authcheck)
        for forbidden in ("grant_type", "client_secret", "refresh_token", "password="):
            self.assertNotIn(forbidden, src)


if __name__ == "__main__":
    unittest.main()
