"""Tests for state normalization (v1 SCREAMING_SNAKE_CASE vs v0 lowercase)."""

import unittest

from a2aops.states import is_terminal, normalize_state, state_class


class TestNormalizeState(unittest.TestCase):
    def test_v1_wire_forms(self):
        for raw, short in [("TASK_STATE_SUBMITTED", "SUBMITTED"),
                           ("TASK_STATE_WORKING", "WORKING"),
                           ("TASK_STATE_INPUT_REQUIRED", "INPUT_REQUIRED"),
                           ("TASK_STATE_AUTH_REQUIRED", "AUTH_REQUIRED"),
                           ("TASK_STATE_COMPLETED", "COMPLETED"),
                           ("TASK_STATE_FAILED", "FAILED"),
                           ("TASK_STATE_CANCELED", "CANCELED"),
                           ("TASK_STATE_REJECTED", "REJECTED")]:
            n = normalize_state(raw)
            self.assertEqual(n.name, short, raw)
            self.assertEqual(n.vocabulary, "v1", raw)
            self.assertTrue(n.known, raw)

    def test_v1_without_prefix(self):
        n = normalize_state("WORKING")
        self.assertEqual((n.name, n.vocabulary), ("WORKING", "v1"))

    def test_v0_lowercase_forms(self):
        cases = {"submitted": "SUBMITTED", "working": "WORKING",
                 "input-required": "INPUT_REQUIRED", "auth-required": "AUTH_REQUIRED",
                 "completed": "COMPLETED", "failed": "FAILED",
                 "canceled": "CANCELED", "rejected": "REJECTED"}
        for raw, short in cases.items():
            n = normalize_state(raw)
            self.assertEqual(n.name, short, raw)
            self.assertEqual(n.vocabulary, "v0", raw)
            self.assertTrue(n.known, raw)

    def test_v0_unknown_is_surfaced_not_silenced(self):
        n = normalize_state("unknown")
        self.assertEqual(n.name, "UNKNOWN")
        self.assertTrue(n.known)
        self.assertEqual(n.vocabulary, "v0")

    def test_unspecified_is_invalid(self):
        n = normalize_state("TASK_STATE_UNSPECIFIED")
        self.assertTrue(n.known)
        self.assertFalse(n.terminal)
        self.assertEqual(state_class("UNSPECIFIED"), "invalid")

    def test_garbage_is_unknown(self):
        n = normalize_state("exploding")
        self.assertFalse(n.known)
        self.assertEqual(n.name, "UNSPECIFIED")

    def test_non_string_is_unknown(self):
        self.assertFalse(normalize_state(None).known)
        self.assertFalse(normalize_state(42).known)
        self.assertFalse(normalize_state("").known)

    def test_terminal_set(self):
        for s in ("COMPLETED", "FAILED", "CANCELED", "REJECTED"):
            self.assertTrue(is_terminal(s), s)
        for s in ("SUBMITTED", "WORKING", "INPUT_REQUIRED", "AUTH_REQUIRED"):
            self.assertFalse(is_terminal(s), s)

    def test_classes(self):
        self.assertEqual(state_class("SUBMITTED"), "active")
        self.assertEqual(state_class("INPUT_REQUIRED"), "interrupted")
        self.assertEqual(state_class("COMPLETED"), "terminal")


if __name__ == "__main__":
    unittest.main()
