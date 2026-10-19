"""End-to-end CLI tests against a live mock agent."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from a2aops import cli
from a2aops.playground import MockAgent

FIX = Path(__file__).with_name("fixtures")


def run_cli(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = MockAgent(name="cli-agent").start()

    @classmethod
    def tearDownClass(cls):
        cls.agent.stop()

    def test_card_check_clean(self):
        code, out = run_cli("card", "check", self.agent.base_url)
        self.assertEqual(code, 0, out)
        self.assertIn("fetched", out)

    def test_card_check_broken(self):
        code, out = run_cli("card", "check", "http://127.0.0.1:1")
        self.assertEqual(code, 2)

    def test_card_fetch(self):
        code, out = run_cli("card", "fetch", self.agent.base_url)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["name"], "cli-agent")

    def test_compat_file_v03(self):
        code, out = run_cli("compat", str(FIX / "card_v03.json"))
        self.assertEqual(code, 1)  # migration actions needed
        self.assertIn("supportedInterfaces", out)

    def test_compat_file_clean(self):
        code, out = run_cli("compat", str(FIX / "card_v1_minimal.json"))
        self.assertEqual(code, 0, out)

    def test_compat_stdin(self):
        card = (FIX / "card_v1_minimal.json").read_text(encoding="utf-8")
        with mock.patch("sys.stdin", io.StringIO(card)):
            code, out = run_cli("compat", "-")
        self.assertEqual(code, 0, out)

    def test_auth_offline(self):
        code, out = run_cli("auth", self.agent.base_url, "--offline")
        self.assertEqual(code, 0, out)

    def test_task_poll(self):
        from a2aops import playground as pg
        resp = pg._rpc(self.agent.base_url + "/", "message/send",
                       {"message": {"messageId": "m1", "role": "user",
                                    "parts": [{"text": "go slow"}]}})
        task_id = resp["result"]["id"]
        code, out = run_cli("task", "poll", self.agent.base_url, task_id,
                            "--binding", "jsonrpc", "--interval", "0.05",
                            "--timeout", "20")
        self.assertEqual(code, 0, out)
        self.assertIn("TASK_STATE_COMPLETED", out)

    def test_task_inspect(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"task_id": "t1", "state": "TASK_STATE_SUBMITTED"}\n')
            f.write('{"task_id": "t1", "state": "TASK_STATE_COMPLETED"}\n')
            path = f.name
        code, out = run_cli("task", "inspect", path)
        self.assertEqual(code, 0, out)
        self.assertIn("no violations", out)

    def test_task_inspect_violation(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"task_id": "t1", "state": "TASK_STATE_FAILED"}\n')
            f.write('{"task_id": "t1", "state": "TASK_STATE_WORKING"}\n')
            path = f.name
        code, out = run_cli("task", "inspect", path)
        self.assertEqual(code, 1, out)
        self.assertIn("T404", out)

    def test_stream(self):
        from a2aops import playground as pg
        resp = pg._rpc(self.agent.base_url + "/", "message/send",
                       {"message": {"messageId": "m1", "role": "user",
                                    "parts": [{"text": "hello"}]}})
        task_id = resp["result"]["id"]
        code, out = run_cli("stream", self.agent.base_url, task_id,
                            "--binding", "jsonrpc", "--max-reconnects", "2")
        self.assertEqual(code, 0, out)
        self.assertIn("closed_on_terminal=True", out)

    def test_play_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = str(Path(tmp) / "demo.jsonl")
            code, out = run_cli("play", "demo", "--log", log)
            self.assertEqual(code, 0, out)
            self.assertTrue(Path(log).exists())
            self.assertIn("planner", out)
