"""Regression tests for the synapse-1 panel review (findings 1-9)."""

import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from a2aops import authcheck, cli, compat, net, report, secreq
from a2aops.card import (CardFetchError, check_card, fetch_card, lint_card,
                         read_card_source, validate_card)
from a2aops.diff import diff_cards
from a2aops.sse import StreamStats

FIX = Path(__file__).with_name("fixtures")


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def codes(diags):
    return [d.code for d in diags]


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def v1_req(*alts):
    """[{"schemes": {name: {"list": scopes}}}] from dicts of name -> scopes."""
    return [{"schemes": {k: {"list": v} for k, v in a.items()}} for a in alts]


# ---------------------------------------------------------------- finding 1

class TestSpecShapedRequirements(unittest.TestCase):
    """a2a.proto: SecurityRequirement { map<string, StringList> schemes = 1; }"""

    def test_fixture_uses_spec_shape(self):
        reqs = load("card_v1_valid.json")["securityRequirements"]
        self.assertEqual(reqs, [{"schemes": {"oidc": {"list": ["bookings:write"]}}}])

    def test_parse_both_shapes(self):
        v1 = secreq.parse(v1_req({"oidc": ["a"], "mtls": []}))
        legacy = secreq.parse([{"oidc": ["a"], "mtls": []}])
        self.assertEqual(v1[0].shape, secreq.V1)
        self.assertEqual(legacy[0].shape, secreq.LEGACY)
        self.assertEqual(v1[0].schemes, legacy[0].schemes)
        # a legacy scheme literally named "schemes" is still legacy
        self.assertEqual(secreq.parse([{"schemes": ["x"]}])[0].shape, secreq.LEGACY)
        self.assertEqual(secreq.parse([{"schemes": {"a": {}}, "b": []}])[0].shape, secreq.INVALID)

    def test_auth_spec_shape_clean(self):
        card = load("card_v1_valid.json")
        diags = authcheck.check_auth_surface(card, check_remote=False)
        self.assertNotIn("E341", codes(diags))
        self.assertEqual([d for d in diags if d.severity == "error"], [])

    def test_auth_spec_shape_ghost_scheme(self):
        diags = authcheck.check_auth_surface(load("card_drifted_auth.json"), check_remote=False)
        msgs = [d.message for d in diags if d.code == "E341"]
        self.assertTrue(any("ghost-scheme" in m for m in msgs), msgs)
        self.assertFalse(any("'schemes'" in m for m in msgs), msgs)

    def test_auth_skill_level_ghost_scheme(self):
        card = load("card_v1_valid.json")
        card["skills"][0]["securityRequirements"] = v1_req({"nope": []})
        diags = authcheck.check_auth_surface(card, check_remote=False)
        self.assertIn("skills[0].securityRequirements[0]", [d.path for d in diags if d.code == "E341"])

    def test_no_false_w202_for_spec_shape(self):
        self.assertNotIn("W202", codes(lint_card(load("card_v1_valid.json"))))

    def test_w202_counts_skill_level_requirements(self):
        card = load("card_v1_valid.json")
        card["securitySchemes"]["key"] = {"apiKeySecurityScheme": {"name": "X", "in": "header"}}
        self.assertIn("W202", codes(lint_card(card)))
        card["skills"][0]["securityRequirements"] = v1_req({"key": []})
        self.assertNotIn("W202", codes(lint_card(card)))

    def test_legacy_shape_accepted_and_flagged(self):
        card = load("card_v1_valid.json")
        card["securityRequirements"] = [{"oidc": ["bookings:write"]}]
        diags = check_card(card)
        self.assertNotIn("E115", codes(diags))
        self.assertIn("I207", codes(diags))
        self.assertNotIn("W202", codes(diags))
        self.assertEqual(codes([d for d in authcheck.check_auth_surface(card, check_remote=False)
                                if d.severity == "error"]), [])
        items = compat.compat_report(card)
        self.assertIn("security-requirement-shape", [i.check for i in items if i.status == "action"])

    def test_malformed_entry_is_e115(self):
        card = load("card_v1_valid.json")
        card["securityRequirements"] = [{"schemes": {"oidc": {}}, "extra": 1}]
        self.assertIn("E115", codes(validate_card(card)))

    def test_v03_security_field(self):
        card = load("card_v1_valid.json")
        card["security"] = card.pop("securityRequirements")
        self.assertIn("I208", codes(lint_card(card)))
        items = compat.compat_report(card)
        self.assertIn("security-field", [i.check for i in items if i.status == "action"])

    def test_diff_detects_alternative_swap_in_spec_shape(self):
        old = load("card_v1_valid.json")
        old["securityRequirements"] = v1_req({"oidc": []}, {"key": []})
        new = copy.deepcopy(old)
        new["securityRequirements"] = v1_req({"mtls": []})
        new["version"] = "3.0.0"
        c = codes(diff_cards(old, new))
        self.assertEqual(c.count("D509"), 2, c)
        self.assertIn("D704", c)

    def test_diff_shape_migration_alone_is_not_breaking(self):
        old = load("card_v1_valid.json")
        old["securityRequirements"] = [{"oidc": ["bookings:write"]}]
        new = load("card_v1_valid.json")
        new["version"] = "2.3.1"
        self.assertEqual(codes(diff_cards(old, new)), [])


# ---------------------------------------------------------------- finding 2

class TestSSRFRanges(unittest.TestCase):
    def check(self, addr):
        net.check_public_url("https://h.example/", resolver=lambda h: [addr])

    def test_blocked(self):
        for addr in ("100.100.100.200",       # CGNAT / Alibaba metadata
                     "100.64.0.1",
                     "64:ff9b::a00:1",        # NAT64 -> 10.0.0.1
                     "64:ff9b::a9fe:a9fe",    # NAT64 -> 169.254.169.254
                     "64:ff9b:1::1",          # local-use NAT64
                     "2002:a00:1::",          # 6to4 -> 10.0.0.1
                     "2001:0:4136:e378:8000:63bf:f5ff:fffe",  # Teredo -> 10.0.0.1
                     "::ffff:100.100.100.200",
                     "fec0::1",               # deprecated site-local
                     "224.0.0.1", "ff02::1", "255.255.255.255",
                     "198.18.0.1", "192.0.0.8", "240.0.0.1", "2001:db8::1"):
            with self.subTest(addr=addr), self.assertRaises(net.UnsafeURL):
                self.check(addr)

    def test_allowed(self):
        for addr in ("93.184.216.34", "8.8.8.8", "2606:4700::1111",
                     "64:ff9b::808:808",       # NAT64 -> 8.8.8.8 (public)
                     "2002:808:808::"):        # 6to4 -> 8.8.8.8 (public)
            with self.subTest(addr=addr):
                self.check(addr)


# ---------------------------------------------------------------- finding 3

class TestOutputCleaned(unittest.TestCase):
    EVIL = "\x1b]0;pwned\x07\x1b[2J\x1b[32mOK"

    def test_stream_notes_cleaned(self):
        stats = StreamStats(notes=[f"duplicate event id {self.EVIL} skipped"])
        with mock.patch("a2aops.sse.stream_with_resubscribe", return_value=stats):
            _, out, _ = run_cli("stream", "http://127.0.0.1:1", "t1")
        self.assertIn("note:", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_task_inspect_error_cleaned(self):
        with mock.patch("a2aops.tasks.observations_from_jsonl", side_effect=ValueError(self.EVIL)):
            code, out, err = run_cli("task", "inspect", "x.jsonl")
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err + out)

    def test_task_inspect_transitions_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "e.jsonl"
            p.write_text(json.dumps({"task_id": "t" + self.EVIL, "state": "TASK_STATE_SUBMITTED"}) + "\n"
                         + json.dumps({"task_id": "t" + self.EVIL, "state": "TASK_STATE_COMPLETED"}) + "\n",
                         encoding="utf-8")
            _, out, _ = run_cli("task", "inspect", str(p))
        self.assertNotIn("\x1b", out)


# ---------------------------------------------------------------- finding 4

class TestMissingFilesAndBadURLs(unittest.TestCase):
    def test_missing_files_never_hit_network(self):
        for src in ("nosuch-card.json", "./nosuch/card.json", "C:\\cards\\agent.json",
                    "~/definitely-missing-a2aops.json", "/no/such/card", "cards\\x"):
            with self.subTest(src=src), mock.patch("a2aops.card.fetch_card") as fetch:
                with self.assertRaises(CardFetchError) as cm:
                    read_card_source(src)
                fetch.assert_not_called()
                self.assertIn("file not found", str(cm.exception))

    def test_cli_missing_file_exit_2(self):
        code, _, err = run_cli("card", "check", "nosuch-card.json")
        self.assertEqual(code, 2)
        self.assertIn("file not found", err)

    def test_bad_urls_are_clean_errors(self):
        for src in ("http://[::1", "https://bad host/", "http://a.example:notaport",
                    "https://" + "a" * 70 + ".example"):
            with self.subTest(src=src), self.assertRaises(CardFetchError):
                fetch_card(src, timeout=1)

    def test_cli_bad_url_exit_2_no_traceback(self):
        code, _, err = run_cli("card", "check", "http://[::1")
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)

    def test_url_with_scheme_and_json_suffix_is_url(self):
        with mock.patch("a2aops.card.fetch_card", return_value=({}, None)) as fetch:
            read_card_source("https://x.example/card.json")
        fetch.assert_called_once()


# ---------------------------------------------------------------- finding 5

class TestDiffGaps(unittest.TestCase):
    def setUp(self):
        self.old = load("card_v1_valid.json")
        self.new = copy.deepcopy(self.old)
        self.new["version"] = "3.0.0"

    def test_extension_becomes_required(self):
        self.old["capabilities"]["extensions"] = [{"uri": "urn:x", "required": False}]
        self.new["capabilities"]["extensions"] = [{"uri": "urn:x", "required": True}]
        self.assertIn("D507", codes(diff_cards(self.old, self.new)))

    def test_extension_already_required_is_quiet(self):
        self.old["capabilities"]["extensions"] = [{"uri": "urn:x", "required": True}]
        self.new["capabilities"]["extensions"] = [{"uri": "urn:x", "required": True}]
        self.assertNotIn("D507", codes(diff_cards(self.old, self.new)))

    def test_inherited_modes_narrowed_by_skill(self):
        self.new["skills"][0]["inputModes"] = ["text/plain"]  # default had application/json too
        self.assertIn("D503", codes(diff_cards(self.old, self.new)))

    def test_explicit_modes_widened_to_inherit_is_quiet(self):
        self.old["skills"][0]["inputModes"] = ["text/plain"]
        self.assertNotIn("D503", codes(diff_cards(self.old, self.new)))

    def test_skill_level_auth_added(self):
        self.new["skills"][0]["securityRequirements"] = v1_req({"oidc": []})
        self.assertIn("D510", codes(diff_cards(self.old, self.new)))

    def test_skill_level_alternative_removed(self):
        self.old["skills"][0]["securityRequirements"] = v1_req({"oidc": []}, {"key": []})
        self.new["skills"][0]["securityRequirements"] = v1_req({"oidc": []})
        self.assertIn("D511", codes(diff_cards(self.old, self.new)))

    def test_v03_security_field_not_false_d508(self):
        old = {"url": "https://a.example/rpc", "preferredTransport": "JSONRPC", "version": "1.0.0",
               "securitySchemes": {"oidc": {}}, "security": [{"oidc": []}]}
        new = {"supportedInterfaces": [{"url": "https://a.example/rpc", "protocolBinding": "JSONRPC",
                                        "protocolVersion": "1.0"}], "version": "2.0.0",
               "securitySchemes": {"oidc": {}}, "securityRequirements": v1_req({"oidc": []})}
        c = codes(diff_cards(old, new))
        self.assertNotIn("D508", c)
        self.assertNotIn("D509", c)

    def test_v03_additional_interfaces(self):
        old = {"url": "https://a.example/rpc", "preferredTransport": "JSONRPC", "version": "1.0.0",
               "additionalInterfaces": [{"url": "https://a.example/rest", "transport": "HTTP+JSON"}]}
        new = {"supportedInterfaces": [{"url": "https://a.example/rpc", "protocolBinding": "JSONRPC",
                                        "protocolVersion": "1.0"}], "version": "2.0.0"}
        removed = [d.message for d in diff_cards(old, new) if d.code == "D501"]
        self.assertEqual(len(removed), 1)
        self.assertIn("https://a.example/rest", removed[0])

    def test_tenant_change_is_interface_change(self):
        self.old["supportedInterfaces"][0]["tenant"] = "acme"
        self.new["supportedInterfaces"][0]["tenant"] = "globex"
        c = codes(diff_cards(self.old, self.new))
        self.assertIn("D501", c)
        self.assertIn("D701", c)


# ---------------------------------------------------------------- finding 6

class TestSarifURIs(unittest.TestCase):
    def test_relative_and_encoded(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(report.path_to_uri("cards/my card.json", cwd=tmp), "cards/my%20card.json")
            self.assertEqual(report.path_to_uri(os.path.join(tmp, "a#b.json"), cwd=tmp), "a%23b.json")

    def test_outside_cwd_is_file_uri(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            uri = report.path_to_uri(os.path.join(b, "x y.json"), cwd=a)
        self.assertTrue(uri.startswith("file:///"), uri)
        self.assertIn("x%20y.json", uri)

    def test_windows_path_has_no_fake_scheme(self):
        import urllib.parse
        uri = report.path_to_uri("C:\\cards\\agent.json", cwd=tempfile.gettempdir())
        self.assertNotEqual(urllib.parse.urlsplit(uri).scheme, "c")

    def test_cli_sarif_uri(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "my card.json"
            p.write_bytes((FIX / "card_v03.json").read_bytes())
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                _, out, _ = run_cli("card", "check", "my card.json", "--format", "sarif")
            finally:
                os.chdir(cwd)
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in json.loads(out)["runs"][0]["results"]}
        self.assertEqual(uris, {"my%20card.json"})


# ---------------------------------------------------------------- finding 7

class TestContentLengthPrecheck(unittest.TestCase):
    def test_precheck_fires_without_reading(self):
        class R:
            headers = {"Content-Length": str(10 ** 9)}

            def read(self, n=-1):
                raise AssertionError("body must not be read when Content-Length is over the cap")

        with self.assertRaises(net.ResponseTooLarge):
            net.read_capped(R(), limit=100)

    def test_malformed_header_falls_back_to_counted_read(self):
        class R:
            headers = {"Content-Length": "lots"}

            def read(self, n=-1):
                return b"x" * min(n, 5)

        self.assertEqual(net.read_capped(R(), limit=10), b"xxxxx")


# ---------------------------------------------------------------- finding 8

class TestCleanInvisibles(unittest.TestCase):
    def test_bidi_and_zero_width(self):
        for ch in ("\u200e", "\u200f", "\u061c", "\u200b", "\u200c", "\u200d",
                   "\u2028", "\u2029", "\u2060", "\ufeff", "\u202e", "\u2066", "\u00ad"):
            with self.subTest(ch=hex(ord(ch))):
                self.assertNotIn(ch, net.clean("a" + ch + "b"))

    def test_normal_unicode_kept(self):
        self.assertEqual(net.clean("café — 東京"), "café — 東京")

    def test_source_has_no_invisible_characters(self):
        src = Path(net.__file__).read_text(encoding="utf-8")
        self.assertIsNone(net._UNSAFE.search(src.replace("\n", "").replace("\t", "")))


# ---------------------------------------------------------------- finding 9

class TestSingleRead(unittest.TestCase):
    def test_file_read_once_and_text_returned(self):
        real_open = open
        calls = []

        def counting_open(path, *a, **kw):
            if str(path).endswith("card_v1_valid.json"):
                calls.append(path)
            return real_open(path, *a, **kw)

        with mock.patch("builtins.open", counting_open):
            code, out, _ = run_cli("card", "check", str(FIX / "card_v1_valid.json"), "--format", "sarif")
        self.assertEqual(len(calls), 1, calls)
        self.assertEqual(code, 0, out)

    def test_cap_enforced_on_the_single_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.json"
            with mock.patch("a2aops.card.MAX_LOCAL_BYTES", 10):
                p.write_text('{"name": "' + "a" * 50 + '"}', encoding="utf-8")
                with self.assertRaises(CardFetchError):
                    read_card_source(str(p))
            src = read_card_source(str(FIX / "card_v1_valid.json"))
        self.assertEqual(json.loads(src.text), src.card)


if __name__ == "__main__":
    unittest.main()
