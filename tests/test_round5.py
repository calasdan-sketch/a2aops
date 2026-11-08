"""Round 5: field-expert angles. Golden files, property tests, mutation sanity, differential checks.

Golden files live in tests/golden/. Regenerate after an intended output change with
``A2AOPS_UPDATE_GOLDEN=1 python -m unittest tests.test_round5`` and review the diff.
"""

import copy
import io
import json
import os
import random
import re
import tempfile
import unittest
import xml.dom.minidom
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import a2aops
from a2aops import cli, conformance, diff, jws, locate, net, suppress
from a2aops.card import ERROR, WARNING, check_card

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
GOLD = ROOT / "tests" / "golden"


def run_cli(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


def norm(text):
    """Make output machine-independent: fixture directory and release number."""
    return text.replace(str(FIX), "<FIX>").replace(a2aops.__version__, "<VERSION>")


# ------------------------------------------------------------------ author

class TestAuthorLine(unittest.TestCase):
    AUTHOR = "Calas Automations Inc."

    def test_pinned_everywhere(self):
        self.assertEqual(a2aops.__author__, self.AUTHOR)
        self.assertIn(f'authors = [{{ name = "{self.AUTHOR}" }}]', (ROOT / "pyproject.toml").read_text())
        self.assertIn(f"Copyright (c) 2026 {self.AUTHOR}", (ROOT / "LICENSE").read_text())
        self.assertNotIn("email", (ROOT / "pyproject.toml").read_text().split("[project.urls]")[0].split("authors")[1][:80])

    def test_old_names_are_gone(self):
        banned = re.compile(r"calasdan|Dan Calas|DC Enterprises", re.I)
        for f in list(ROOT.glob("*.md")) + list(ROOT.glob("*.toml")) + list((ROOT / "src" / "a2aops").glob("*.py")) \
                + list((ROOT / "docs").glob("*.md")) + [ROOT / "LICENSE", ROOT / "action.yml"]:
            self.assertIsNone(banned.search(f.read_text(encoding="utf-8")), f.name)

    def test_tool_metadata_names_the_author(self):
        code, out, _ = run_cli("card", "check", str(FIX / "card_v1_valid.json"), "--format", "sarif")
        driver = json.loads(out)["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["organization"], self.AUTHOR)
        self.assertEqual(driver["informationUri"], "https://calasautomations.com")
        code, out, _ = run_cli("card", "check", str(FIX / "card_v1_valid.json"), "--format", "junit")
        self.assertIn(self.AUTHOR, out)
        xml.dom.minidom.parseString(out)
        code, out, _ = run_cli("--help")
        self.assertIn(self.AUTHOR, out)


# ------------------------------------------------------------------ golden

GOLDEN_CASES = {
    "check_broken": ["card", "check", "{F}/card_broken.json"],
    "check_v03": ["card", "check", "{F}/card_v03.json"],
    "check_security_types": ["card", "check", "{F}/card_bad_security_types.json"],
    "diff_minimal_to_valid": ["card", "diff", "{F}/card_v1_minimal.json", "{F}/card_v1_valid.json"],
    "diff_valid_to_minimal": ["card", "diff", "{F}/card_v1_valid.json", "{F}/card_v1_minimal.json"],
    "compat_v03": ["compat", "{F}/card_v03.json"],
    "auth_drifted": ["auth", "--offline", "{F}/card_drifted_auth.json"],
}
FORMATS = {"text": [], "json": ["--format", "json"], "sarif": ["--format", "sarif"], "junit": ["--format", "junit"]}


class TestGoldenOutputs(unittest.TestCase):
    """Every output format of the main commands, byte for byte."""

    def _check(self, name, argv):
        code, out, err = run_cli(*[a.replace("{F}", str(FIX)) for a in argv])
        text = norm(out) + (f"--- stderr ---\n{norm(err)}" if err else "") + f"--- exit {code} ---\n"
        path = GOLD / f"{name}.txt"
        if os.environ.get("A2AOPS_UPDATE_GOLDEN"):
            GOLD.mkdir(exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        self.assertTrue(path.exists(), f"missing golden file {path.name}")
        self.assertEqual(text, path.read_text(encoding="utf-8"), f"{path.name} changed")

    def test_card_check_diff_every_format(self):
        for name, argv in GOLDEN_CASES.items():
            for fmt, extra in FORMATS.items():
                if name.startswith(("compat", "auth")) and fmt not in ("text",):
                    continue
                with self.subTest(name=name, fmt=fmt):
                    self._check(f"{name}.{fmt}", argv + extra)

    def test_explain_one_and_all(self):
        self._check("explain_E341", ["explain", "E341"])
        self._check("explain_W217", ["explain", "W217"])

    def test_every_sarif_is_valid_json_and_junit_valid_xml(self):
        for name, argv in GOLDEN_CASES.items():
            if name.startswith(("compat", "auth")):
                continue
            a = [x.replace("{F}", str(FIX)) for x in argv]
            _, s, _ = run_cli(*a, "--format", "sarif")
            self.assertEqual(json.loads(s)["version"], "2.1.0")
            _, j, _ = run_cli(*a, "--format", "junit")
            xml.dom.minidom.parseString(j)


# ------------------------------------------------- generators (seeded, no deps)

_LEAVES = [None, True, False, 0, 1, -1, 2**70, 1.5, "", "x", "https://a.example/x", "JSONRPC", "text/plain",
           "\x1b[31m", "‮", [], {}, [1], ["a"], {"a": 1}, [{}]]


def _paths(o, p=()):
    yield p
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, p + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, p + (i,))


def mutate(card, rnd, n=None):
    c = copy.deepcopy(card)
    for _ in range(n or rnd.choice([1, 1, 2, 3])):
        ps = [p for p in _paths(c) if p]
        p = rnd.choice(ps)
        try:
            parent = c
            for k in p[:-1]:
                parent = parent[k]
            if rnd.random() < 0.3:
                del parent[p[-1]]
            else:
                parent[p[-1]] = copy.deepcopy(rnd.choice(_LEAVES))
        except (KeyError, IndexError, TypeError):
            pass
    return c


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


BASES = ["card_v1_valid.json", "card_v1_minimal.json", "card_v1_unusual_valid.json"]


class TestProperties(unittest.TestCase):
    def test_check_card_never_raises_and_is_deterministic(self):
        rnd = random.Random(2605)
        for _ in range(600):
            c = mutate(load(rnd.choice(BASES)), rnd)
            a = [(d.severity, d.code, d.path, d.message) for d in check_card(c)]
            b = [(d.severity, d.code, d.path, d.message) for d in check_card(copy.deepcopy(c))]
            self.assertEqual(a, b)
            for _sev, code, path, _msg in a:
                self.assertRegex(code, r"^[EWIS]\d{3}$")
                self.assertIsInstance(path, str)

    def test_key_order_does_not_change_findings(self):
        rnd = random.Random(7)
        for _ in range(200):
            c = mutate(load(rnd.choice(BASES)), rnd)

            def shuffled(o):
                if isinstance(o, dict):
                    items = [(k, shuffled(v)) for k, v in o.items()]
                    rnd.shuffle(items)
                    return dict(items)
                if isinstance(o, list):
                    return [shuffled(x) for x in o]
                return o
            a = sorted((d.code, d.path) for d in check_card(c))
            b = sorted((d.code, d.path) for d in check_card(shuffled(c)))
            self.assertEqual(a, b)

    def test_diff_of_a_card_with_itself_is_silent(self):
        rnd = random.Random(11)
        for _ in range(300):
            c = mutate(load(rnd.choice(BASES)), rnd)
            bad = [d for d in diff.diff_cards(c, copy.deepcopy(c)) if d.severity in (ERROR, WARNING)]
            self.assertEqual(bad, [], c)

    def test_removing_a_skill_is_breaking_and_adding_it_back_is_not(self):
        base = load("card_v1_valid.json")
        for sk in base["skills"]:
            smaller = copy.deepcopy(base)
            smaller["skills"] = [s for s in smaller["skills"] if s["id"] != sk["id"]]
            self.assertTrue(any(d.severity == ERROR for d in diff.diff_cards(base, smaller)))
            self.assertFalse(any(d.severity == ERROR for d in diff.diff_cards(smaller, base)))

    def test_diff_never_raises_on_two_mutated_cards(self):
        rnd = random.Random(13)
        for _ in range(400):
            a = mutate(load(rnd.choice(BASES)), rnd)
            b = mutate(load(rnd.choice(BASES)), rnd)
            diff.diff_cards(a, b)
            diff.check_bump(a, b)

    def test_baseline_roundtrip_hides_everything_it_recorded(self):
        rnd = random.Random(17)
        with tempfile.TemporaryDirectory() as d:
            for i in range(60):
                diags = check_card(mutate(load(rnd.choice(BASES)), rnd))
                p = os.path.join(d, f"b{i}.json")
                suppress.write_baseline(p, diags)
                kept, hidden = suppress.apply(diags, [], suppress.load_baseline(p))
                self.assertEqual(kept, [])
                self.assertEqual(hidden, len(diags))

    def test_sarif_lines_stay_inside_the_file(self):
        rnd = random.Random(19)
        for _ in range(60):
            c = mutate(load(rnd.choice(BASES)), rnd)
            text = json.dumps(c, indent=2)
            n = text.count("\n") + 1
            idx = locate.LineIndex(text)
            for d in check_card(c):
                ln = idx.line(d.path)
                if ln is not None:
                    self.assertTrue(1 <= ln <= n, (d.path, ln, n))

    def test_json_canonicalization_agrees_with_the_stdlib_on_bmp_data(self):
        """Differential: RFC 8785 output equals json.dumps(sort_keys, compact) for ints/strings/containers."""
        rnd = random.Random(23)
        alphabet = "abcXYZ019 _-éü中\u0007\"\\/"

        def gen(depth=0):
            r = rnd.random()
            if depth > 3 or r < 0.3:
                return rnd.choice([None, True, False, rnd.randint(-10**6, 10**6), "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 6)))])
            if r < 0.6:
                return [gen(depth + 1) for _ in range(rnd.randint(0, 3))]
            return {"".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 4))): gen(depth + 1)
                    for _ in range(rnd.randint(0, 4))}
        for _ in range(500):
            v = gen()
            self.assertEqual(jws.canonicalize(v), json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False))

    def test_strict_loader_agrees_with_json_loads_unless_duplicates_or_constants(self):
        rnd = random.Random(29)
        for _ in range(400):
            c = mutate(load(rnd.choice(BASES)), rnd)
            text = json.dumps(c)
            self.assertEqual(net.loads_strict(text), json.loads(text))
        for bad in ('{"a":1,"a":2}', '{"x":{"a":1,"a":1}}', '[NaN]', '{"a":Infinity}', '[-Infinity]'):
            with self.assertRaises(ValueError):
                net.loads_strict(bad)


# ------------------------------------------- security-scheme structure (SDK differential)

class TestSecuritySchemeTypes(unittest.TestCase):
    def codes(self, card):
        return {(d.code, d.path) for d in check_card(card)}

    def test_fixture_reports_each_wrong_type(self):
        got = self.codes(load("card_bad_security_types.json"))
        for want in [
            ("E120", "securitySchemes.oidc.openIdConnectSecurityScheme.openIdConnectUrl"),
            ("E120", "securitySchemes.key.apiKeySecurityScheme.name"),
            ("E120", "securitySchemes.oauth.oauth2SecurityScheme.flows.clientCredentials.scopes"),
            ("E120", "securitySchemes.broken"),
            ("E120", "securityRequirements[0].schemes.oidc.list"),
            ("E120", "securityRequirements[0].schemes.oauth"),
            ("W217", "securityRequirements[0].schemes.key"),
        ]:
            self.assertIn(want, got)

    def test_valid_security_is_untouched(self):
        for name in BASES:
            self.assertFalse([d for d in check_card(load(name)) if d.severity == ERROR], name)

    def test_non_object_scheme_and_kind(self):
        c = load("card_v1_valid.json")
        c["securitySchemes"]["x"] = {"apiKeySecurityScheme": "oops"}
        self.assertIn(("E120", "securitySchemes.x.apiKeySecurityScheme"), self.codes(c))

    def test_agrees_with_official_sdk_parser_when_installed(self):
        try:
            from a2a.types import AgentCard
            from google.protobuf import json_format
        except Exception:                                  # noqa: BLE001
            self.skipTest("a2a-sdk is not installed (pip install a2a-sdk)")
        rnd = random.Random(5)
        missed = []
        for _ in range(1500):
            c = mutate(load("card_v1_valid.json"), rnd, n=1)
            try:
                json_format.ParseDict(copy.deepcopy(c), AgentCard())
                continue
            except Exception:                              # noqa: BLE001
                pass
            errs = [d for d in check_card(c) if d.severity == ERROR and not d.code.startswith("S")]
            warns = [d for d in check_card(c) if d.code in ("W210", "W217")]
            if not errs and not warns:
                missed.append(c)
        # what is left is deliberate: unknown fields never fail (policy), and a requirement whose
        # "schemes" is a list is a legal pre-1.0 scheme literally named "schemes" (see secreq)
        for c in missed:
            self.assertTrue(
                any(k == "a" for k in _walk_keys(c))
                or any(isinstance(v, dict) and isinstance(v.get("schemes"), list) for v in _walk_values(c)),
                json.dumps(c)[:300])


def _walk_values(o):
    yield o
    if isinstance(o, dict):
        for v in o.values():
            yield from _walk_values(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk_values(v)


def _walk_keys(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk_keys(v)


# ------------------------------------------------------------- conformance SSRF

class TestConformanceDoesNotProbeInward(unittest.TestCase):
    def ctx(self, base, urls, **kw):
        x = conformance.Ctx(base, **kw)
        x.card = {"supportedInterfaces": [{"url": u, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
                                          for u in urls]}
        conformance._select_interfaces(x)
        return x

    def test_public_card_cannot_aim_probes_at_metadata_or_private_hosts(self):
        for bad in ("http://169.254.169.254/latest", "http://10.0.0.5:8080/", "http://localhost:9/",
                    "http://[::1]:9/", "http://metadata.google.internal/", "http://100.100.100.200/"):
            x = self.ctx("https://agent.example.com", [bad])
            self.assertIsNone(x.jsonrpc, bad)
            self.assertEqual(len(x.refused), 1, bad)

    def test_public_and_same_host_interfaces_still_work(self):
        x = self.ctx("https://93.184.216.34", ["https://93.184.216.34/a2a"])
        self.assertIsNotNone(x.jsonrpc)
        self.assertEqual(x.refused, [])

    def test_local_base_or_explicit_flag_allows_private_endpoints(self):
        self.assertIsNotNone(self.ctx("http://127.0.0.1:9", ["http://10.0.0.5/"]).jsonrpc)
        self.assertIsNotNone(self.ctx("https://agent.example.com", ["http://10.0.0.5/"],
                                      allow_private_endpoints=True).jsonrpc)

    def test_flag_exists_on_the_command_line(self):
        code, out, err = run_cli("conformance", "--help")
        self.assertIn("--allow-private-endpoints", out)


# ------------------------------------------------------------------ --output

class TestOutputFile(unittest.TestCase):
    def test_report_goes_to_the_file_not_stdout_and_exit_code_is_kept(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.sarif")
            code, so, se = run_cli("card", "check", str(FIX / "card_broken.json"), "--format", "sarif", "--output", out)
            self.assertEqual(code, 1)
            self.assertEqual(so, "")
            self.assertIn("wrote report", se)
            raw = Path(out).read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r", raw)
            self.assertEqual(json.loads(raw.decode("utf-8"))["version"], "2.1.0")
            self.assertEqual([p.name for p in Path(d).iterdir()], ["r.sarif"])      # no temp file left

    def test_a_failed_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            Path(out).write_text("old report")
            code, so, se = run_cli("card", "check", os.path.join(d, "missing.json"), "--output", out)
            self.assertEqual(code, 2)
            self.assertEqual(Path(out).read_text(), "old report")      # a stale file is never silently replaced

    def test_write_baseline_with_output_leaves_no_empty_report(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.txt")
            code, so, se = run_cli("card", "check", str(FIX / "card_broken.json"), "--write-baseline",
                                   os.path.join(d, "b.json"), "--output", out)
            self.assertEqual(code, 0)
            self.assertFalse(os.path.exists(out))

    def test_unwritable_target_is_a_plain_error(self):
        with tempfile.TemporaryDirectory() as d:
            code, so, se = run_cli("card", "check", str(FIX / "card_v1_valid.json"),
                                   "--output", os.path.join(d, "no", "such", "dir", "r.txt"))
            self.assertEqual(code, 2)
            self.assertIn("cannot write", se)

    def test_non_ascii_survives(self):
        with tempfile.TemporaryDirectory() as d:
            card = json.loads((FIX / "card_v1_valid.json").read_text())
            card["skills"][0]["name"] = "caf\u00e9 \u4e2d\u6587"
            src = os.path.join(d, "c.json")
            Path(src).write_text(json.dumps(card, ensure_ascii=False), encoding="utf-8")
            out = os.path.join(d, "o.json")
            run_cli("card", "check", src, "--format", "json", "--output", out)
            self.assertEqual(json.loads(Path(out).read_text(encoding="utf-8"))["command"], "card-check")


# ------------------------------------------------------------ diff robustness

class TestDiffHostileExtensions(unittest.TestCase):
    def test_unhashable_extension_uri_does_not_crash(self):
        a = load("card_v1_valid.json")
        b = copy.deepcopy(a)
        for uri in ({"x": 1}, [1, 2], None, 7, True):
            a["capabilities"]["extensions"] = [{"uri": uri, "required": False}]
            b["capabilities"]["extensions"] = [{"uri": uri, "required": True}]
            diff.diff_cards(a, b)
        a["capabilities"]["extensions"] = [{"uri": "https://x.example/e"}]
        b["capabilities"]["extensions"] = [{"uri": "https://x.example/e", "required": True}]
        self.assertTrue(any(d.code == "D507" for d in diff.diff_cards(a, b)))


class TestRedirectsCannotReachInward(unittest.TestCase):
    """A public endpoint answering 307 -> http://localhost:PORT/ must not move a GET probe into the private network."""

    def _servers(self):
        import http.server
        import threading
        hits = []

        class B(http.server.BaseHTTPRequestHandler):
            def _h(self):
                hits.append(self.command)
                self.send_response(404)
                self.end_headers()
            do_GET = do_POST = _h

            def log_message(self, *a):
                pass
        sb = http.server.HTTPServer(("127.0.0.1", 0), B)
        pb = sb.server_address[1]

        class A(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/rest"):
                    return self.do_POST()
                card = load("card_v1_valid.json")
                card["supportedInterfaces"] = [{"url": f"http://127.0.0.1:{sa.server_address[1]}/rest",
                                                "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}]
                data = json.dumps(card).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(307)
                self.send_header("Location", f"http://localhost:{pb}/internal")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        sa = http.server.HTTPServer(("127.0.0.1", 0), A)
        for sv in (sa, sb):
            threading.Thread(target=sv.serve_forever, daemon=True).start()
        return sa, sb, hits

    def _probe(self, **kw):
        from unittest import mock
        sa, sb, hits = self._servers()
        try:
            # pretend the tested URL is a public one, so the guard is active
            with mock.patch.object(conformance, "_is_local", lambda url: False):
                conformance.run(f"http://127.0.0.1:{sa.server_address[1]}", only_ids={"REST-04"}, timeout=3.0, **kw)
        finally:
            sa.shutdown()
            sb.shutdown()
        return hits

    def test_redirect_into_private_network_is_refused(self):
        self.assertEqual(self._probe(), [])
        self.assertIsNone(net.redirect_guard)                  # never left installed

    def test_flag_restores_following(self):
        self.assertTrue(self._probe(allow_private_endpoints=True))


# ------------------------------------------------------------------ CORS probe

class TestCorsProbe(unittest.TestCase):
    def _run(self, mutant=None):
        from a2aops.playground import MockAgent
        from bench.mutants import MUTANTS, MutantProxy
        agent = MockAgent("ref", legacy=False).start()
        try:
            chosen = next(m for m in MUTANTS if m.name == mutant) if mutant else None
            px = MutantProxy(agent.base_url, chosen).start()
            try:
                _, res = conformance.run(px.url, only_ids={"RPC-30", "REST-30"}, timeout=5.0)
            finally:
                px.stop()
        finally:
            agent.stop()
        return {r.id: r.status for r in res}

    def test_clean_agent_passes(self):
        self.assertEqual(self._run(), {"RPC-30": conformance.PASS, "REST-30": conformance.PASS})

    def test_reflecting_agent_is_flagged(self):
        got = self._run("cors-reflect-credentials")
        self.assertEqual(got, {"RPC-30": conformance.WARN, "REST-30": conformance.WARN})

    def test_wildcard_without_credentials_is_fine(self):
        self.assertEqual(conformance._cors_reflection({"access-control-allow-origin": "*"}), "")
        self.assertEqual(conformance._cors_reflection(
            {"access-control-allow-origin": conformance._PROBE_ORIGIN}), "")       # reflected but no credentials
        self.assertNotEqual(conformance._cors_reflection(
            {"access-control-allow-origin": conformance._PROBE_ORIGIN, "access-control-allow-credentials": "true"}), "")


if __name__ == "__main__":
    unittest.main()
