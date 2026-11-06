"""Tests for 1.2.0: file/stdin input, card diff, JSON/SARIF output, hardening."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from a2aops import authcheck, cli, net
from a2aops.card import CardFetchError, Diagnostic, fetch_card, load_card_source
from a2aops.diff import diff_cards
from a2aops.report import failed, to_sarif

from test_card import CardServer

FIX = Path(__file__).with_name("fixtures")


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def run_cli(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        if stdin is not None:
            with mock.patch("sys.stdin", io.StringIO(stdin)):
                code = cli.main(list(argv))
        else:
            code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def codes(diags):
    return [d.code for d in diags]


class TestLocalSources(unittest.TestCase):
    def test_card_check_file_clean(self):
        code, out, _ = run_cli("card", "check", str(FIX / "card_v1_valid.json"))
        self.assertEqual(code, 0, out)
        self.assertIn("read ", out)

    def test_card_check_file_errors(self):
        code, out, _ = run_cli("card", "check", str(FIX / "card_v03.json"))
        self.assertEqual(code, 1)
        self.assertIn("E101", out)

    def test_card_check_stdin(self):
        code, out, _ = run_cli("card", "check", "-",
                               stdin=(FIX / "card_v1_minimal.json").read_text())
        self.assertEqual(code, 0, out)

    def test_malformed_file_is_error_not_url_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.json"
            p.write_text("{not json", encoding="utf-8")
            with mock.patch("a2aops.card.fetch_card") as fetch:
                code, _, err = run_cli("compat", str(p))
            fetch.assert_not_called()
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_directory_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CardFetchError):
                load_card_source(tmp)

    def test_bom_file_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bom.json"
            p.write_bytes(b"\xef\xbb\xbf" + (FIX / "card_v1_minimal.json").read_bytes())
            card, info = load_card_source(str(p))
        self.assertIsNone(info)
        self.assertIn("name", card)

    def test_strict_fails_on_warnings(self):
        card = load("card_v1_minimal.json")
        card["description"] = "x"  # W203
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.json"
            p.write_text(json.dumps(card), encoding="utf-8")
            self.assertEqual(run_cli("card", "check", str(p))[0], 0)
            self.assertEqual(run_cli("card", "check", str(p), "--strict")[0], 1)

    def test_auth_from_file_offline(self):
        code, out, _ = run_cli("auth", str(FIX / "card_drifted_auth.json"), "--offline")
        self.assertEqual(code, 1)
        self.assertIn("E341", out)


class TestCardPathAndCaps(unittest.TestCase):
    def test_custom_card_path(self):
        body = json.dumps(load("card_v1_minimal.json")).encode()
        srv = CardServer({"/cards/a.json": (200, body)})
        try:
            card, info = fetch_card(srv.base, card_path="/cards/a.json")
            self.assertEqual(info.path_used, "/cards/a.json")
            self.assertFalse(info.legacy_fallback)
            with self.assertRaises(CardFetchError) as cm:
                fetch_card(srv.base, card_path="/missing.json")
            self.assertIn("/missing.json", str(cm.exception))
        finally:
            srv.stop()

    def test_card_path_must_be_a_path(self):
        for bad in ("cards/a.json", "http://evil/x", "//evil/x://"):
            with self.assertRaises(CardFetchError):
                fetch_card("http://127.0.0.1:1", card_path=bad)

    def test_oversized_card_refused(self):
        big = b'{"name": "' + b"a" * (net.MAX_DOC_BYTES + 10) + b'"}'
        srv = CardServer({"/.well-known/agent-card.json": (200, big)})
        try:
            with self.assertRaises(CardFetchError) as cm:
                fetch_card(srv.base)
            self.assertIn("cap", str(cm.exception))
        finally:
            srv.stop()

    def test_read_capped_without_content_length(self):
        class R:
            headers = {}

            def __init__(self, data):
                self.data = io.BytesIO(data)

            def read(self, n=-1):
                return self.data.read(n)

        self.assertEqual(net.read_capped(R(b"abc"), limit=3), b"abc")
        with self.assertRaises(net.ResponseTooLarge):
            net.read_capped(R(b"abcd"), limit=3)


class TestSSRFGuard(unittest.TestCase):
    def resolver(self, mapping):
        return lambda host: mapping[host]

    def test_public_https_allowed(self):
        net.check_public_url("https://login.example.com/x",
                             self.resolver({"login.example.com": ["93.184.216.34"]}))

    def test_blocked_targets(self):
        cases = {
            "https://meta.internal/": ["169.254.169.254"],
            "https://lo.example/": ["127.0.0.1"],
            "https://ten.example/": ["10.0.0.5"],
            "https://v6.example/": ["::1"],
            "https://mapped.example/": ["::ffff:192.168.1.1"],
            "https://mixed.example/": ["93.184.216.34", "10.1.1.1"],
            "https://zero.example/": ["0.0.0.0"],
        }
        for url, addrs in cases.items():
            host = url.split("/")[2]
            with self.subTest(url=url), self.assertRaises(net.UnsafeURL):
                net.check_public_url(url, self.resolver({host: addrs}))

    def test_scheme_and_credentials(self):
        r = self.resolver({"a.example": ["93.184.216.34"]})
        for url in ("http://a.example/", "file:///etc/passwd", "https://u:p@a.example/",
                    "https://a.example:99999/", "https:///nohost"):
            with self.subTest(url=url), self.assertRaises(net.UnsafeURL):
                net.check_public_url(url, r)

    def test_auth_reports_blocked_fetch_as_warning(self):
        card = load("card_v1_valid.json")
        card["securitySchemes"]["oidc"]["openIdConnectSecurityScheme"]["openIdConnectUrl"] = \
            "https://127.0.0.1/.well-known/openid-configuration"
        diags = authcheck.check_auth_surface(card, timeout=1)
        self.assertIn("W307", codes(diags))
        self.assertNotIn("E303", codes(diags))

    def test_plain_http_oidc_not_fetched(self):
        card = load("card_v1_valid.json")
        card["securitySchemes"]["oidc"]["openIdConnectSecurityScheme"]["openIdConnectUrl"] = \
            "http://169.254.169.254/latest"
        with mock.patch.object(authcheck, "_fetch_json") as f:
            diags = authcheck.check_auth_surface(card)
        f.assert_not_called()
        self.assertIn("E302", codes(diags))

    def test_redirect_to_private_is_blocked(self):
        handler = net._GuardedRedirects(self.resolver({"internal.example": ["10.0.0.1"]}))
        with self.assertRaises(net.UnsafeURL):
            handler.redirect_request(None, None, 302, "Found", {}, "https://internal.example/x")

    def test_allow_private_reaches_local_server(self):
        doc = json.dumps({"issuer": "http://127.0.0.1", "token_endpoint": "x"}).encode()
        srv = CardServer({"/oidc": (200, doc)})
        try:
            got, err = authcheck._fetch_json(srv.base + "/oidc", 5, allow_private=True)
            self.assertIsNone(err)
            self.assertEqual(got["token_endpoint"], "x")
            got, err = authcheck._fetch_json(srv.base + "/oidc", 5)
            self.assertIsNone(got)
            self.assertIsInstance(err, authcheck._Blocked)
        finally:
            srv.stop()


class TestTerminalSafety(unittest.TestCase):
    def test_clean_escapes_controls(self):
        s = net.clean("ok\x1b[2J\x1b]0;pwned\x07\nnext\u202ehi\x9b")
        for bad in ("\x1b", "\x07", "\n", "\u202e", "\x9b"):
            self.assertNotIn(bad, s)
        self.assertIn("\\x1b", s)
        self.assertIn("\\u202e", s)

    def test_hostile_card_does_not_emit_escape(self):
        card = load("card_v1_minimal.json")
        card["version"] = "\x1b[32mOK\x1b[0m"
        card["skills"].append({"id": card["skills"][0]["id"] + "\x1b[2J"})
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.json"
            p.write_text(json.dumps(card), encoding="utf-8")
            _, out, _ = run_cli("card", "check", str(p))
        self.assertNotIn("\x1b", out)


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.old = load("card_v1_valid.json")

    def test_identical_is_clean(self):
        self.assertEqual(diff_cards(self.old, copy.deepcopy(self.old)), [])

    def test_additive_change_is_info_only(self):
        new = copy.deepcopy(self.old)
        new["version"] = "2.4.0"
        new["skills"].append({"id": "cancel", "name": "c", "description": "d", "tags": ["x"]})
        diags = diff_cards(self.old, new)
        self.assertEqual(codes(diags), ["D702"])
        self.assertFalse(failed(diags))

    def test_skill_removed_is_breaking(self):
        new = copy.deepcopy(self.old)
        new["skills"] = []
        new["version"] = "3.0.0"
        self.assertIn("D502", codes(diff_cards(self.old, new)))

    def test_unbumped_version_warns(self):
        new = copy.deepcopy(self.old)
        new["description"] = "Something else entirely, but longer."
        self.assertEqual(codes(diff_cards(self.old, new)), ["D607"])

    def test_breaking_without_major_bump(self):
        new = copy.deepcopy(self.old)
        new["capabilities"]["streaming"] = False
        new["version"] = "2.4.0"
        c = codes(diff_cards(self.old, new))
        self.assertIn("D506", c)
        self.assertIn("D608", c)

    def test_auth_added_is_breaking(self):
        old = load("card_v1_minimal.json")
        new = copy.deepcopy(old)
        new["securitySchemes"] = {"k": {"apiKeySecurityScheme": {"name": "X", "in": "header"}}}
        new["securityRequirements"] = [{"k": []}]
        self.assertIn("D508", codes(diff_cards(old, new)))

    def test_auth_removed_is_warning_not_breaking(self):
        new = copy.deepcopy(self.old)
        new["securityRequirements"] = []
        new["version"] = "2.4.0"
        diags = diff_cards(self.old, new)
        self.assertIn("D605", codes(diags))
        self.assertNotIn("D509", codes(diags))

    def test_auth_alternative_swapped(self):
        new = copy.deepcopy(self.old)
        new["securityRequirements"] = [{"oidc": [], "mtls": []}]
        new["version"] = "3.0.0"
        c = codes(diff_cards(self.old, new))
        self.assertIn("D509", c)
        self.assertIn("D704", c)

    def test_preferred_interface_reordered(self):
        new = copy.deepcopy(self.old)
        new["supportedInterfaces"].reverse()
        new["version"] = "2.3.1"
        self.assertEqual(codes(diff_cards(self.old, new)), ["D601"])

    def test_v03_to_v1_same_endpoint_is_not_removal(self):
        old = {"url": "https://a.example/rpc", "preferredTransport": "JSONRPC", "version": "1"}
        new = {"supportedInterfaces": [{"url": "https://a.example/rpc", "protocolBinding": "JSONRPC",
                                        "protocolVersion": "1.0"}], "version": "2"}
        self.assertNotIn("D501", codes(diff_cards(old, new)))

    def test_new_required_extension(self):
        new = copy.deepcopy(self.old)
        new["capabilities"]["extensions"] = [{"uri": "urn:x", "required": True}]
        new["version"] = "3.0.0"
        self.assertIn("D507", codes(diff_cards(self.old, new)))

    def test_garbage_input_never_crashes(self):
        junk = [None, 1, "x", [], {"skills": "nope", "supportedInterfaces": [1, None, {}],
                                   "capabilities": [], "securityRequirements": [1, "a"],
                                   "securitySchemes": [], "defaultInputModes": [1]}]
        for a in junk:
            for b in junk:
                diff_cards(a, b)

    def test_cli_diff_and_stdin(self):
        code, out, _ = run_cli("card", "diff", str(FIX / "card_v1_valid.json"), "-",
                               stdin=(FIX / "card_v1_valid.json").read_text())
        self.assertEqual(code, 0, out)
        code, _, _ = run_cli("card", "diff", "-", "-", stdin="{}")
        self.assertEqual(code, 2)


class TestOutputFormats(unittest.TestCase):
    def test_json_output(self):
        code, out, _ = run_cli("card", "check", str(FIX / "card_v03.json"), "--format", "json")
        doc = json.loads(out)
        self.assertEqual(code, 1)
        self.assertFalse(doc["ok"])
        self.assertGreater(doc["counts"]["error"], 0)
        self.assertIn("E101", [f["code"] for f in doc["findings"]])

    def test_sarif_output_shape(self):
        code, out, _ = run_cli("card", "check", str(FIX / "card_v03.json"), "--format", "sarif")
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids)
            self.assertIn(res["level"], ("error", "warning", "note"))
            loc = res["locations"][0]["physicalLocation"]
            self.assertTrue(loc["artifactLocation"]["uri"].endswith("card_v03.json"))
            self.assertGreaterEqual(loc["region"]["startLine"], 1)

    def test_sarif_line_lookup(self):
        text = '{\n  "name": "x",\n  "skills": [\n    {"id": "a"}\n  ]\n}'
        out = json.loads(to_sarif([Diagnostic("error", "E111", "m", "skills[0].tags"),
                                   Diagnostic("error", "E101", "m", "skills")],
                                  command="t", artifact_uri="c.json", source_text=text))
        lines = [r["locations"][0]["physicalLocation"]["region"]["startLine"]
                 for r in out["runs"][0]["results"]]
        self.assertEqual(lines, [1, 3])

    def test_compat_json(self):
        code, out, _ = run_cli("compat", str(FIX / "card_v03.json"), "--format", "json")
        doc = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(doc["detected_card_version"], "0.x")
        self.assertTrue(any(i["status"] == "action" for i in doc["items"]))


if __name__ == "__main__":
    unittest.main()
