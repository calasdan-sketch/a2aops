"""Tests for the task lifecycle inspector."""

import json
import tempfile
import unittest
from pathlib import Path

from a2aops import tasks as tasks_mod
from a2aops.tasks import (Observation, TaskInspector, observations_from_jsonl,
                          poll_task)


def obs(task_id, state, message=None):
    return Observation(task_id=task_id, state=state, message=message)


class TestInspector(unittest.TestCase):
    def test_happy_path_no_violations(self):
        insp = TaskInspector()
        for s in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED"):
            insp.observe(obs("t1", s))
        self.assertEqual(insp.report(), [])
        self.assertEqual(insp.current_states(), {"t1": "COMPLETED"})

    def test_transition_out_of_terminal_is_error(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "TASK_STATE_COMPLETED"))
        insp.observe(obs("t1", "TASK_STATE_WORKING"))
        codes = [d.code for d in insp.report()]
        self.assertIn("T404", codes)

    def test_self_transition_on_terminal_is_fine(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "TASK_STATE_FAILED"))
        insp.observe(obs("t1", "TASK_STATE_FAILED"))
        self.assertEqual([d for d in insp.report() if d.code == "T404"], [])

    def test_unspecified_is_error(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "TASK_STATE_UNSPECIFIED"))
        self.assertTrue(any(d.code == "T403" for d in insp.report()))

    def test_garbage_state_is_error(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "melting"))
        self.assertTrue(any(d.code == "T402" for d in insp.report()))

    def test_v0_unknown_flagged_as_removed(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "unknown"))
        self.assertTrue(any(d.code == "T401" for d in insp.report()))

    def test_v0_vocabulary_normalized(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "submitted"))
        insp.observe(obs("t1", "input-required", message="which color?"))
        insp.observe(obs("t1", "working"))
        insp.observe(obs("t1", "completed"))
        self.assertEqual(insp.report(), [])
        self.assertEqual(insp.current_states(), {"t1": "COMPLETED"})

    def test_input_required_without_message_warns(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "TASK_STATE_INPUT_REQUIRED"))
        self.assertTrue(any(d.code == "T405" for d in insp.report()))

    def test_input_required_with_message_ok(self):
        insp = TaskInspector()
        insp.observe(obs("t1", "TASK_STATE_INPUT_REQUIRED", message="need a date"))
        self.assertEqual([d for d in insp.report() if d.code == "T405"], [])

    def test_does_not_enforce_unpublished_transitions(self):
        """D5: SUBMITTED -> COMPLETED directly is unusual but not a violation."""
        insp = TaskInspector()
        insp.observe(obs("t1", "TASK_STATE_SUBMITTED"))
        insp.observe(obs("t1", "TASK_STATE_COMPLETED"))
        self.assertEqual(insp.report(), [])
        tr = insp.transitions()
        self.assertEqual(len(tr), 1)
        self.assertEqual((tr[0].from_state, tr[0].to_state), ("SUBMITTED", "COMPLETED"))

    def test_multiple_tasks_tracked_independently(self):
        insp = TaskInspector()
        insp.observe(obs("a", "TASK_STATE_WORKING"))
        insp.observe(obs("b", "TASK_STATE_COMPLETED"))
        insp.observe(obs("a", "TASK_STATE_COMPLETED"))
        self.assertEqual(insp.report(), [])
        self.assertEqual(insp.summary()["tasks_observed"], 2)

    def test_summary_counts(self):
        insp = TaskInspector()
        insp.observe(obs("a", "TASK_STATE_WORKING"))
        insp.observe(obs("b", "TASK_STATE_FAILED"))
        s = insp.summary()
        self.assertEqual(s["current_by_class"], {"active": 1, "terminal": 1})


class TestJsonl(unittest.TestCase):
    def test_load_observations(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"task_id": "t1", "state": "TASK_STATE_SUBMITTED"}\n')
            f.write('{"task_id": "t1", "state": "TASK_STATE_COMPLETED", "message": "ok"}\n')
            path = f.name
        obss = observations_from_jsonl(path)
        self.assertEqual(len(obss), 2)
        self.assertEqual(obss[1].message, "ok")

    def test_bad_line_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"task_id": "t1"}\n')
            path = f.name
        with self.assertRaises(ValueError):
            observations_from_jsonl(path)


class TestPoll(unittest.TestCase):
    def test_polls_until_terminal(self):
        states = [{"status": {"state": "TASK_STATE_WORKING"}},
                  {"status": {"state": "TASK_STATE_WORKING"}},
                  {"status": {"state": "TASK_STATE_COMPLETED"}}]
        calls = {"n": 0}

        def fake_fetch(base, tid):
            calls["n"] += 1
            return states[min(calls["n"] - 1, 2)]

        insp = poll_task("https://x.example", "t1", fetch=fake_fetch, interval=0,
                         timeout=60, sleep=lambda s: None, clock=lambda: 0.0)
        self.assertEqual(insp.current_states(), {"t1": "COMPLETED"})
        self.assertEqual(calls["n"], 3)

    def test_timeout_warns(self):
        def fake_fetch(base, tid):
            return {"status": {"state": "TASK_STATE_WORKING"}}

        ticks = {"t": 0.0}
        insp = poll_task("https://x.example", "t1", fetch=fake_fetch, interval=0,
                         timeout=5, sleep=lambda s: None,
                         clock=lambda: ticks.__setitem__("t", ticks["t"] + 10) or ticks["t"])
        self.assertTrue(any(d.code == "T411" for d in insp.report()))

    def test_poll_failure_recorded(self):
        def fake_fetch(base, tid):
            raise ConnectionError("down")

        insp = poll_task("https://x.example", "t1", fetch=fake_fetch,
                         sleep=lambda s: None, clock=lambda: 0.0)
        self.assertTrue(any(d.code == "T410" for d in insp.report()))


if __name__ == "__main__":
    unittest.main()


class TestPlaygroundLogShapes(unittest.TestCase):
    """The offline inspector must read playground wire logs directly."""

    def test_accepts_playground_entries_and_skips_non_task_lines(self):
        lines = [
            '{"ts": 1.0, "kind": "agent_started", "agent": "a"}',
            '{"ts": 2.0, "kind": "task_polled", "task_id": "t1", "state": "TASK_STATE_WORKING"}',
            '{"ts": 3.0, "kind": "task_created", "task": {"id": "t2", "status": {"state": "TASK_STATE_COMPLETED"}}}',
            '{"ts": 4.0, "kind": "task_terminal", "task_id": "t1", "state": "TASK_STATE_COMPLETED"}',
            '{"ts": 5.0, "kind": "error", "message": "boom"}',
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write("\n".join(lines) + "\n")
            path = f.name
        obss = observations_from_jsonl(path)
        self.assertEqual(
            [(o.task_id, o.state) for o in obss],
            [("t1", "TASK_STATE_WORKING"),
             ("t2", "TASK_STATE_COMPLETED"),
             ("t1", "TASK_STATE_COMPLETED")],
        )

    def test_playground_demo_log_feeds_inspector_end_to_end(self):
        from a2aops.playground import demo_scenario, run_scenario

        with tempfile.TemporaryDirectory() as tmp:
            log = str(Path(tmp) / "session.jsonl")
            run_scenario(demo_scenario(), log)
            obss = observations_from_jsonl(log)
            self.assertTrue(obss, "expected observations from the demo log")
            insp = TaskInspector()
            for o in obss:
                insp.observe(o)
            errors = [d for d in insp.report() if d.severity == "error"]
            self.assertEqual(errors, [], [str(d) for d in errors])
