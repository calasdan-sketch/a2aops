"""Round 3: strict JSON, read deadline, SSE caps, suppression/baselines, explain, line locator."""

import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from a2aops import cli, explain, jws, net, sse, suppress
from a2aops.card import Diagnostic
from a2aops.locate import LineIndex
from a2aops.report import to_sarif

FIX = Path(__file__).with_name("fixtures")
SRC = Path(__file__).resolve().parents[1] / "src" / "a2aops"


def run_cli(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        if stdin is not None:
            with mock.patch("sys.stdin", io.StringIO(stdin)):
                code = cli.main(list(argv))
        else:
            code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestStrictJson(unittest.TestCase):
    def test_accepts_normal(self):
        self.assertEqual(net.loads_strict('{"a": [1, 2.5, null, "x"]}'), {"a": [1, 2.5, None, "x"]})

    def test_duplicate_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate key 'a'"):
            net.loads_strict('{"a": 1, "a": 2}')

    def test_nested_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            net.loads_strict('{"x": [{"k": 1, "k": 1}]}')

    def test_nan_and_infinity_rejected(self):
        for bad in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(ValueError, msg=bad):
                net.loads_strict('{"v": %s}' % bad)

    def test_hundred_thousand_deep_is_a_clean_error(self):
        with self.assertRaisesRegex(ValueError, "deeper"):
            net.loads_strict("[" * 100_000 + "]" * 100_000)

    def test_depth_limit_boundary(self):
        ok = "[" * net.MAX_JSON_DEPTH + "]" * net.MAX_JSON_DEPTH
        net.loads_strict(ok)
        with self.assertRaises(ValueError):
            net.loads_strict("[" + ok + "]")

    @unittest.skipUnless(hasattr(sys, "set_int_max_str_digits"), "needs the int-digits limit (3.10.7+)")
    def test_huge_integer_rejected(self):
        with self.assertRaises(ValueError):
            net.loads_strict("9" * 6000)

    def test_cli_reports_duplicate_key_as_operational_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text('{"name": "a", "name": "b"}')
            code, out, err = run_cli("card", "check", str(p))
        self.assertEqual(code, 2)
        self.assertIn("duplicate key", err)

    def test_cli_deep_file_does_not_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text('{"extensions": ' + "[" * 50_000 + "]" * 50_000 + "}")
            code, out, err = run_cli("card", "check", str(p))
        self.assertEqual(code, 2)
        self.assertIn("deeper", err)

    def test_duplicate_alg_in_jws_header_is_malformed(self):
        hdr = jws.b64u_encode(b'{"alg":"ES256","alg":"none"}')
        outcome, _ = jws.verify_signature({}, {"protected": hdr, "signature": "AAAA"}, [])
        self.assertEqual(outcome, jws.Outcome.MALFORMED)


class TestReadDeadline(unittest.TestCase):
    def test_slow_drip_is_cut_off(self):
        clock = {"t": 0.0}

        class Drip:
            headers = {}

            def read(self, n=-1):
                clock["t"] += 10.0          # every byte takes 10 s
                return b"x"

        with mock.patch.object(net.time, "monotonic", lambda: clock["t"]):
            with self.assertRaisesRegex(net.ResponseTooLarge, "still arriving"):
                net.read_capped(Drip(), limit=1 << 20, max_seconds=25)

    def test_normal_read_unchanged(self):
        class R:
            headers = {}
            data = [b"ab", b"cd", b""]

            def read(self, n=-1):
                return R.data.pop(0)

        self.assertEqual(net.read_capped(R(), limit=10), b"abcd")


class TestSseCaps(unittest.TestCase):
    def test_overlong_line_raises(self):
        class R:
            def readline(self, size=-1):
                return b"d" * size

        with self.assertRaises(sse.SSELineTooLong):
            next(sse._line_iter(R()))

    def test_stream_exit_code_when_gave_up(self):
        stats = sse.StreamStats()
        stats.gave_up = True
        with mock.patch.object(sse, "stream_with_resubscribe", return_value=stats):
            code, out, _ = run_cli("stream", "http://127.0.0.1:9", "t1")
        self.assertEqual(code, 1)

    def test_stream_exit_code_ok(self):
        with mock.patch.object(sse, "stream_with_resubscribe", return_value=sse.StreamStats()):
            code, _, _ = run_cli("stream", "http://127.0.0.1:9", "t1")
        self.assertEqual(code, 0)


class TestSuppress(unittest.TestCase):
    def card(self, d):
        d = Path(d)
        card = json.loads((FIX / "card_v1_valid.json").read_text())
        card["description"] = "x"
        card["skills"].append(dict(card["skills"][0], id="second", tags=[]))
        p = d / "c.json"
        p.write_text(json.dumps(card, indent=2))
        return str(p)

    def test_parse_ignore(self):
        self.assertEqual(suppress.parse_ignore(["w203, s8", "E1"]), ["W203", "S8", "E1"])
        for bad in ("all", "*", "203", "W2033", "../x"):
            with self.assertRaises(suppress.SuppressError, msg=bad):
                suppress.parse_ignore([bad])

    def test_ignore_flag(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.card(d)
            code, out, _ = run_cli("card", "check", c)
            self.assertEqual(code, 1)
            code, out, _ = run_cli("card", "check", c, "--ignore", "E112", "--ignore", "W203")
            self.assertEqual(code, 0, out)
            self.assertIn("2 finding(s) hidden", out)

    def test_ignore_prefix_matches_family_only(self):
        diags = [Diagnostic("error", "E112", "m", "a"), Diagnostic("error", "E1120"[:4], "m", "b"),
                 Diagnostic("warning", "W203", "m", "c")]
        kept, hidden = suppress.apply(diags, ["E1"], None)
        self.assertEqual([d.code for d in kept], ["W203"])
        self.assertEqual(hidden, 2)

    def test_baseline_roundtrip_hides_old_fails_new(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.card(d)
            b = str(Path(d) / "base.json")
            code, _, err = run_cli("card", "check", c, "--write-baseline", b)
            self.assertEqual(code, 0)
            self.assertIn("wrote 2", err)
            code, out, _ = run_cli("card", "check", c, "--baseline", b)
            self.assertEqual(code, 0, out)
            card = json.loads(Path(c).read_text())
            del card["name"]                       # a new problem
            Path(c).write_text(json.dumps(card, indent=2))
            code, out, _ = run_cli("card", "check", c, "--baseline", b)
            self.assertEqual(code, 1)
            self.assertIn("E101", out)

    def test_baseline_is_stable_across_runs(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.card(d)
            run_cli("card", "check", c, "--write-baseline", str(Path(d) / "a.json"))
            run_cli("card", "check", c, "--write-baseline", str(Path(d) / "b.json"))
            self.assertEqual((Path(d) / "a.json").read_text(), (Path(d) / "b.json").read_text())

    def test_bad_baselines_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.card(d)
            for name, content in (("missing.json", None), ("junk.json", "{nope"),
                                  ("wrong.json", '{"hello": 1}'),
                                  ("dup.json", '{"a2aops_baseline":1,"a2aops_baseline":1,"findings":[]}'),
                                  ("rows.json", '{"a2aops_baseline":1,"findings":[5]}')):
                p = Path(d) / name
                if content is not None:
                    p.write_text(content)
                code, out, err = run_cli("card", "check", c, "--baseline", str(p))
                self.assertEqual(code, 2, name)
                self.assertIn("baseline", err)

    def test_both_baseline_flags_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.card(d)
            code, _, err = run_cli("card", "check", c, "--baseline", "a", "--write-baseline", "b")
            self.assertEqual(code, 2)

    def test_json_output_reports_suppressed_count(self):
        with tempfile.TemporaryDirectory() as d:
            c = self.card(d)
            code, out, _ = run_cli("card", "check", c, "--ignore", "E112,W203", "--format", "json")
            doc = json.loads(out)
            self.assertEqual(doc["suppressed"], 2)
            self.assertTrue(doc["ok"])

    def test_diff_and_auth_accept_ignore(self):
        a, b = str(FIX / "card_v1_valid.json"), str(FIX / "card_v1_minimal.json")
        code, _, _ = run_cli("card", "diff", a, b)
        code2, _, _ = run_cli("card", "diff", a, b, "--ignore", "D,E,W,I")
        self.assertEqual(code2, 0)
        code3, _, _ = run_cli("auth", a, "--offline", "--ignore", "E3")
        self.assertIn(code3, (0, 1))


class TestExplain(unittest.TestCase):
    def test_every_emitted_code_is_explained(self):
        emitted = set()
        for f in SRC.glob("*.py"):
            emitted |= set(re.findall(r'"([EWIDSGT][0-9]{3})"', f.read_text(encoding="utf-8")))
        emitted.discard("E000")
        missing = sorted(emitted - set(explain.CODES))
        self.assertEqual(missing, [], f"codes without an `a2aops explain` entry: {missing}")

    def test_no_stale_entries(self):
        emitted = set()
        for f in SRC.glob("*.py"):
            if f.name != "explain.py":
                emitted |= set(re.findall(r'"([EWIDSGT][0-9]{3})"', f.read_text(encoding="utf-8")))
        stale = sorted(set(explain.CODES) - emitted)
        self.assertEqual(stale, [], f"explain entries for codes nothing emits: {stale}")

    def test_cli(self):
        code, out, _ = run_cli("explain", "e341")
        self.assertEqual(code, 0)
        self.assertIn("meaning:", out)
        self.assertEqual(out.count("\n"), 3)       # real lines, not escaped \n
        code, out, _ = run_cli("explain", "E999")
        self.assertEqual(code, 2)
        code, out, _ = run_cli("explain")
        self.assertEqual(code, 0)
        self.assertGreater(out.count("\n"), 100)


class TestLocator(unittest.TestCase):
    def setUp(self):
        card = json.loads((FIX / "card_v1_valid.json").read_text())
        card["skills"].append(dict(card["skills"][0], id="second", tags=[]))
        self.text = json.dumps(card, indent=2)
        self.lines = self.text.splitlines()
        self.ix = LineIndex(self.text)

    def at(self, path):
        return self.lines[self.ix.line(path) - 1].strip()

    def test_indexed_and_id_paths_hit_the_right_skill(self):
        self.assertEqual(self.at("skills[1].tags"), '"tags": []')
        self.assertEqual(self.at("skills[id=second].tags"), '"tags": []')
        self.assertNotEqual(self.ix.line("skills[0].tags"), self.ix.line("skills[1].tags"))

    def test_missing_key_falls_back_to_parent(self):
        self.assertEqual(self.ix.line("skills[1].nothing"), self.ix.line("skills[1]"))

    def test_garbage_is_safe(self):
        for t in ("", "{", '{"a": ', '"\\', "[[[[", "\x00\x01"):
            LineIndex(t).line("a.b[0]")

    def test_strings_with_structural_chars(self):
        t = '{\n "a": "}{[,:",\n "b": {"c": "x"}\n}'
        self.assertEqual(LineIndex(t).line("b.c"), 3)

    def test_sarif_fingerprints_are_unique_per_result(self):
        ds = [Diagnostic("warning", "S801", "a", "name"), Diagnostic("warning", "S801", "b", "name"),
              Diagnostic("warning", "S801", "c", "other")]
        doc = json.loads(to_sarif(ds, command="t", artifact_uri="c.json"))
        fps = [r["partialFingerprints"]["a2aopsFinding/v1"] for r in doc["runs"][0]["results"]]
        self.assertEqual(len(set(fps)), 3)
        self.assertEqual(fps[0].split(":")[0], fps[1].split(":")[0])

    def test_sarif_has_line_and_fingerprint(self):
        d = Diagnostic("error", "E112", "m", "skills[1].tags")
        doc = json.loads(to_sarif([d], command="t", artifact_uri="c.json", source_text=self.text))
        res = doc["runs"][0]["results"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], self.ix.line("skills[1].tags"))
        self.assertEqual(res["partialFingerprints"]["a2aopsFinding/v1"], suppress.fingerprint(d))


class TestOutputEncoding(unittest.TestCase):
    def test_lone_surrogate_in_skill_id_does_not_crash_diff(self):
        old = json.loads((FIX / "card_v1_valid.json").read_text())
        new = json.loads(json.dumps(old))
        new["skills"][0]["id"] = "\ud800x"
        new["version"] = "9.0.0"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "o.json").write_text(json.dumps(old))
            (Path(d) / "n.json").write_text(json.dumps(new))
            for fmt in ("text", "junit", "json", "sarif"):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    cli.main(["card", "diff", str(Path(d) / "o.json"), str(Path(d) / "n.json"), "--format", fmt])
                out.getvalue().encode("utf-8")      # strict: raises on a surrogate

    def test_clean_escapes_surrogates(self):
        self.assertEqual(net.clean("a\ud800b"), "a\\ud800b")


class TestConformanceSelection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from a2aops.playground import MockAgent
        cls.agent = MockAgent(name="r3").start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def test_unknown_only_id_is_an_error_not_a_green_empty_run(self):
        code, out, err = run_cli("conformance", self.agent.base_url, "--only", "NOPE-99")
        self.assertEqual(code, 2)
        self.assertIn("unknown check id", err)

    def test_only_is_case_insensitive_and_runs_one_check(self):
        code, out, _ = run_cli("conformance", self.agent.base_url, "--only", "card-01")
        self.assertEqual(code, 0)
        self.assertIn("1 passed", out)

    def test_skip_removes_a_check(self):
        _, with_it, _ = run_cli("conformance", self.agent.base_url, "--only", "CARD-01,CARD-02", "--format", "json")
        _, without, _ = run_cli("conformance", self.agent.base_url, "--only", "CARD-01,CARD-02",
                                "--skip", "CARD-02", "--format", "json")
        ids = lambda o: [r["id"] for r in json.loads(o)["results"]]   # noqa: E731
        self.assertEqual(ids(with_it), ["CARD-01", "CARD-02"])
        self.assertEqual(ids(without), ["CARD-01"])

    def test_only_and_skip_cancelling_out_is_an_error(self):
        code, _, err = run_cli("conformance", self.agent.base_url, "--only", "CARD-01", "--skip", "CARD-01")
        self.assertEqual(code, 2)

    def test_skip_typo_is_an_error(self):
        code, _, err = run_cli("conformance", self.agent.base_url, "--skip", "CARD-99")
        self.assertEqual(code, 2)


class TestMessages(unittest.TestCase):
    def test_wrong_element_type_is_named(self):
        from a2aops.card import validate_card
        card = json.loads((FIX / "card_v1_valid.json").read_text())
        card["skills"][0]["inputModes"] = [3]
        msgs = [d.message for d in validate_card(card)] + [d.message for d in __import__("a2aops.schema", fromlist=["x"]).validate_structure(card)]
        self.assertTrue(any("array containing number" in m for m in msgs), msgs)


if __name__ == "__main__":
    unittest.main()
