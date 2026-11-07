"""Round 4: what a stranger who installs the package actually meets."""

import http.server
import io
import re
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import a2aops
from a2aops import cli, net, suppress, wire
from a2aops.card import Diagnostic
from a2aops.playground import Scenario
from a2aops.tasks import observations_from_jsonl

FIX = Path(__file__).with_name("fixtures")
ROOT = Path(__file__).resolve().parents[1]


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:        # argparse usage errors
            code = e.code
    return code, out.getvalue(), err.getvalue()


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestRedirectsDoNotLeakCredentials(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen

        class Target(http.server.BaseHTTPRequestHandler):
            def do_GET(h):
                seen.append((h.headers.get("Authorization"), h.headers.get("X-Api-Key")))
                h.send_response(200)
                h.send_header("Content-Type", "application/json")
                h.end_headers()
                h.wfile.write(b"{}")
            do_POST = do_GET

            def log_message(*a):
                pass

        self.target = _serve(Target)
        tport = self.target.server_port
        self.location = f"http://localhost:{tport}/x"

        outer = self

        class Redirector(http.server.BaseHTTPRequestHandler):
            def do_GET(h):
                h.send_response(302)
                h.send_header("Location", outer.location)
                h.end_headers()
            do_POST = do_GET

            def log_message(*a):
                pass

        self.redir = _serve(Redirector)
        self.addCleanup(self.target.shutdown)
        self.addCleanup(self.redir.shutdown)

    def test_cross_origin_redirect_drops_credentials(self):
        r = wire.http_request("GET", f"http://127.0.0.1:{self.redir.server_port}/",
                              headers={"Authorization": "Bearer t", "X-Api-Key": "k", "Accept": "*/*"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.seen, [(None, None)])

    def test_redirect_to_ftp_is_refused(self):
        self.location = "ftp://example.invalid/x"
        r = wire.http_request("GET", f"http://127.0.0.1:{self.redir.server_port}/")
        self.assertNotEqual(r.status, 200)

    def test_same_origin_redirect_keeps_headers(self):
        # Target redirecting to itself on the same origin keeps the header.
        self.location = f"http://127.0.0.1:{self.redir.server_port}/again"
        class_seen = []
        orig = self.redir.RequestHandlerClass.do_GET
        count = {"n": 0}

        def do_get(h):
            count["n"] += 1
            if count["n"] == 1:
                return orig(h)
            class_seen.append(h.headers.get("Authorization"))
            h.send_response(200)
            h.send_header("Content-Type", "application/json")
            h.end_headers()
            h.wfile.write(b"{}")
        self.redir.RequestHandlerClass.do_GET = do_get
        wire.http_request("GET", f"http://127.0.0.1:{self.redir.server_port}/",
                          headers={"Authorization": "Bearer t"})
        self.assertEqual(class_seen, ["Bearer t"])


class TestUrlHandling(unittest.TestCase):
    def test_non_http_schemes_refused(self):
        for u in ("file:///etc/hostname", "ftp://example.invalid/x", "gopher://x/"):
            code, out, err = run_cli("card", "check", u)
            self.assertEqual(code, 2, u)
            self.assertIn("only http and https", err)
            self.assertNotIn("Traceback", err)

    def test_password_in_url_is_not_echoed(self):
        secret = "".join(["hun", "ter2"])
        code, out, err = run_cli("card", "check", f"http://user:{secret}@127.0.0.1:9/")
        self.assertEqual(code, 2)
        self.assertNotIn(secret, out + err)
        self.assertIn("***@", err)

    def test_redact_url(self):
        self.assertEqual(net.redact_url("https://a.example/x"), "https://a.example/x")
        self.assertEqual(net.redact_url("https://u:p@a.example:8443/x?q=1"), "https://***@a.example:8443/x?q=1")
        self.assertEqual(net.redact_url("not a url"), "not a url")


class TestOptionValidation(unittest.TestCase):
    def test_bad_timeouts_are_usage_errors(self):
        card = str(FIX / "card_v1_valid.json")
        for bad in ("0", "-5", "nan", "inf", "abc"):
            code, out, err = run_cli("card", "check", card, "--timeout", bad)
            self.assertEqual(code, 2, bad)
            self.assertIn("timeout", err)

    def test_negative_reconnects_rejected(self):
        code, _, err = run_cli("stream", "http://127.0.0.1:9", "t", "--max-reconnects", "-1")
        self.assertEqual(code, 2)


class TestPlaygroundErrors(unittest.TestCase):
    def test_bad_log_path_is_a_plain_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, err = run_cli("play", "demo", "--log", str(Path(d) / "no" / "such" / "x.jsonl"))
        self.assertEqual(code, 2)
        self.assertIn("cannot write the session log", err)
        self.assertNotIn("Traceback", err)

    def test_malformed_scenarios_raise_valueerror(self):
        for bad in ([], {"agents": "x"}, {"agents": [{"nom": "a"}]}, {"agents": [], "script": [{"from": "a"}]},
                    {"agents": [], "script": "go"}, {"agents": [], "script": [{"from": 1, "to": "b", "text": "t"}]}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                Scenario.from_dict(bad)

    def test_play_run_reports_bad_scenario(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text('{"agents":[{"name":"a"}],"script":[{"from":"a"}]}')
            code, out, err = run_cli("play", "run", str(p), "--log", str(Path(d) / "l.jsonl"))
        self.assertEqual(code, 2)
        self.assertIn("script step 1", err)


class TestTaskInspectErrors(unittest.TestCase):
    def test_missing_file_message(self):
        code, _, err = run_cli("task", "inspect", "definitely-not-here.jsonl")
        self.assertEqual(code, 2)
        self.assertIn("file not found", err)

    def test_non_numeric_ts(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e.jsonl"
            p.write_text('{"task_id":"t","state":"TASK_STATE_WORKING","ts":null}\n')
            with self.assertRaisesRegex(ValueError, "'ts' must be a number"):
                observations_from_jsonl(str(p))
            code, _, err = run_cli("task", "inspect", str(p))
        self.assertEqual(code, 2)


class TestBaselineWrite(unittest.TestCase):
    def test_atomic_write_leaves_no_temp_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            n = suppress.write_baseline(str(p), [Diagnostic("error", "E101", "x", "name")])
            self.assertEqual(n, 1)
            self.assertEqual([f.name for f in Path(d).iterdir()], ["b.json"])
            self.assertEqual(suppress.load_baseline(str(p)), {suppress.fingerprint(Diagnostic("error", "E101", "y", "name"))})

    def test_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "b.json"
            p.write_text("old")
            suppress.write_baseline(str(p), [])
            self.assertIn("a2aops_baseline", p.read_text())


class TestPackagingMetadata(unittest.TestCase):
    """Cheap guards so a release cannot ship with drifting metadata."""

    def test_versions_agree(self):
        py = (ROOT / "pyproject.toml").read_text()
        m = re.search(r'^version = "([^"]+)"', py, re.M)
        self.assertEqual(m.group(1), a2aops.__version__)
        head = re.search(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(), re.M)
        self.assertEqual(head.group(1), a2aops.__version__)

    def test_license_and_typed_marker_present(self):
        self.assertTrue((ROOT / "LICENSE").read_text().startswith("MIT License"))
        self.assertTrue((ROOT / "src" / "a2aops" / "py.typed").exists())
        py = (ROOT / "pyproject.toml").read_text()
        self.assertIn('license = "MIT"', py)
        self.assertIn("py.typed", py)

    def test_readme_test_count_not_stale(self):
        # The README states how many tests exist; keep it honest.
        readme = (ROOT / "README.md").read_text()
        m = re.search(r"# (\d+) tests", readme)
        self.assertIsNotNone(m)
        n = sum(len(re.findall(r"^    def test_", p.read_text(), re.M))
                for p in (ROOT / "tests").glob("test_*.py"))
        self.assertLessEqual(abs(int(m.group(1)) - n), 25, f"README says {m.group(1)}, found ~{n} test methods")


if __name__ == "__main__":
    unittest.main()
