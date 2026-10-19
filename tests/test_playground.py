"""Tests for the playground: mock agents, SSE, scenario runs."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from a2aops import playground
from a2aops.card import fetch_card, validate_card, has_errors
from a2aops.playground import MockAgent, Scenario, demo_scenario, run_scenario
from a2aops.sse import stream_with_resubscribe
from a2aops.tasks import TaskInspector, Observation


def rpc(url, method, params):
    return playground._rpc(url, method, params)


class TestMockAgent(unittest.TestCase):
    def setUp(self):
        self.agent = MockAgent(name="test-agent").start()

    def tearDown(self):
        self.agent.stop()

    def test_serves_valid_card(self):
        card, info = fetch_card(self.agent.base_url)
        self.assertFalse(has_errors(validate_card(card)))
        self.assertEqual(card["name"], "test-agent")
        self.assertEqual(info.status, 200)

    def test_message_send_completes(self):
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "hello"}]}})
        task = resp["result"]
        self.assertEqual(task["status"]["state"], "TASK_STATE_COMPLETED")
        self.assertTrue(task["artifacts"])

    def test_fail_keyword(self):
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "please fail this"}]}})
        self.assertEqual(resp["result"]["status"]["state"], "TASK_STATE_FAILED")

    def test_need_input_keyword(self):
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "need input here"}]}})
        task = resp["result"]
        self.assertEqual(task["status"]["state"], "TASK_STATE_INPUT_REQUIRED")
        self.assertTrue(task["status"]["message"])

    def test_slow_task_advances_on_poll(self):
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "go slow"}]}})
        task_id = resp["result"]["id"]
        states = set()
        for _ in range(10):
            got = rpc(self.agent.base_url + "/", "tasks/get", {"id": task_id})
            states.add(got["result"]["status"]["state"])
            if got["result"]["status"]["state"] == "TASK_STATE_COMPLETED":
                break
        self.assertIn("TASK_STATE_COMPLETED", states)

    def test_cancel(self):
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "go slow"}]}})
        task_id = resp["result"]["id"]
        cancelled = rpc(self.agent.base_url + "/", "tasks/cancel", {"id": task_id})
        self.assertEqual(cancelled["result"]["status"]["state"], "TASK_STATE_CANCELED")

    def test_stream_closes_on_terminal(self):
        # create a completed task, then resubscribe-stream it
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "hello"}]}})
        task_id = resp["result"]["id"]
        seen = []
        stats = stream_with_resubscribe(self.agent.base_url, task_id, binding="jsonrpc",
                                        on_event=seen.append, sleep=lambda s: None,
                                        max_reconnects=2)
        self.assertTrue(stats.closed_on_terminal)
        self.assertGreaterEqual(stats.events, 1)

    def test_message_stream_replays_transitions(self):
        """The fixture must stream real transitions, not just the final state."""
        import json as _json
        import urllib.request as _url

        payload = _json.dumps({"jsonrpc": "2.0", "id": "s1", "method": "message/stream",
                               "params": {"message": {"messageId": "m1", "role": "user",
                                                      "parts": [{"text": "hello"}]}}}).encode()
        req = _url.Request(self.agent.base_url + "/", data=payload,
                           headers={"Content-Type": "application/json",
                                    "Accept": "text/event-stream"})
        states = []
        with _url.urlopen(req, timeout=15) as resp:
            self.assertEqual(resp.headers.get_content_type(), "text/event-stream")
            from a2aops.sse import parse_sse_stream
            for ev in parse_sse_stream(
                    (line.decode() for line in resp)):
                if ev.comment is not None or not ev.data:
                    continue
                body = _json.loads(ev.data)
                states.append(body["status"]["state"])
        self.assertEqual(states[:3],
                         ["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED"])
        self.assertGreaterEqual(len(states), 3)

    def test_rest_tasks_get(self):
        from a2aops.tasks import rest_get_task
        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "hello"}]}})
        task_id = resp["result"]["id"]
        task = rest_get_task(self.agent.base_url, task_id)
        self.assertEqual(task["status"]["state"], "TASK_STATE_COMPLETED")


class TestScenario(unittest.TestCase):
    def test_demo_run_produces_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = str(Path(tmp) / "session.jsonl")
            report = run_scenario(demo_scenario(), log)
            self.assertEqual(report.steps, 3)
            self.assertEqual(set(report.agents), {"planner", "worker"})
            lines = Path(log).read_text(encoding="utf-8").strip().split("\n")
            self.assertGreater(len(lines), 5)
            kinds = {json.loads(l)["kind"] for l in lines}
            self.assertTrue({"agent_started", "message_send", "task_created",
                             "task_terminal"} <= kinds)
            # every log line carries a timestamp
            for line in lines:
                self.assertIn("ts", json.loads(line))

    def test_scenario_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            scen_path = Path(tmp) / "scen.json"
            scen_path.write_text(json.dumps({
                "agents": [{"name": "solo"}],
                "script": [{"from": "you", "to": "solo", "text": "hi"}],
            }), encoding="utf-8")
            scen = Scenario.from_json(str(scen_path))
            report = run_scenario(scen, str(Path(tmp) / "out.jsonl"))
            self.assertEqual(report.steps, 1)

    def test_log_feeds_inspector_cleanly(self):
        """The playground's wire log must not trip the lifecycle inspector."""
        with tempfile.TemporaryDirectory() as tmp:
            log = str(Path(tmp) / "session.jsonl")
            run_scenario(demo_scenario(), log)
            insp = TaskInspector()
            for line in Path(log).read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                if row["kind"] == "task_polled":
                    insp.observe(Observation(task_id=row["task_id"],
                                             state=row["state"]))
            errors = [d for d in insp.report() if d.severity == "error"]
            self.assertEqual(errors, [], [str(d) for d in errors])


if __name__ == "__main__":
    unittest.main()


class TestRestResubscribe(unittest.TestCase):
    """The fixture must serve the REST resubscribe path too, so the CLI's
    default `stream --binding rest` works against the playground."""

    def setUp(self):
        self.agent = MockAgent(name="test-agent").start()

    def tearDown(self):
        self.agent.stop()

    def test_rest_subscribe_returns_sse_snapshot(self):
        import urllib.request as _url

        resp = rpc(self.agent.base_url + "/", "message/send",
                   {"message": {"messageId": "m1", "role": "user",
                                "parts": [{"text": "hello"}]}})
        task_id = resp["result"]["id"]
        body = json.dumps({"id": task_id, "historyLength": 0}).encode()
        req = _url.Request(f"{self.agent.base_url}/v1/tasks/{task_id}:subscribe",
                           data=body,
                           headers={"Content-Type": "application/json",
                                    "Accept": "text/event-stream"})
        with _url.urlopen(req, timeout=15) as http_resp:
            self.assertEqual(http_resp.headers.get_content_type(), "text/event-stream")
            from a2aops.sse import parse_sse_stream
            events = [ev for ev in parse_sse_stream(
                (line.decode() for line in http_resp)) if ev.data]
        self.assertTrue(events, "expected at least one SSE event")
        body = json.loads(events[0].data)
        self.assertEqual(body["taskId"], task_id)
        self.assertEqual(body["status"]["state"], "TASK_STATE_COMPLETED")
        self.assertTrue(body["final"])

    def test_rest_subscribe_unknown_task_is_final(self):
        import urllib.request as _url

        body = json.dumps({"id": "task-9999", "historyLength": 0}).encode()
        req = _url.Request(f"{self.agent.base_url}/v1/tasks/task-9999:subscribe",
                           data=body,
                           headers={"Content-Type": "application/json",
                                    "Accept": "text/event-stream"})
        with _url.urlopen(req, timeout=15) as http_resp:
            from a2aops.sse import parse_sse_stream
            events = [ev for ev in parse_sse_stream(
                (line.decode() for line in http_resp)) if ev.data]
        body = json.loads(events[0].data)
        self.assertEqual(body["status"]["state"], "TASK_STATE_UNSPECIFIED")
        self.assertTrue(body["final"])
