"""Tests for version detection and migration reports."""

import json
import unittest
from pathlib import Path

from a2aops.compat import (compat_report, detect_card_version, format_report,
                            needs_migration)

FIX = Path(__file__).with_name("fixtures")


def load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class TestDetect(unittest.TestCase):
    def test_v1_detected(self):
        self.assertEqual(detect_card_version(load("card_v1_valid.json")), "1.0")
        self.assertEqual(detect_card_version(load("card_v1_minimal.json")), "1.0")

    def test_v0_detected(self):
        self.assertEqual(detect_card_version(load("card_v03.json")), "0.x")

    def test_unknown(self):
        self.assertEqual(detect_card_version({}), "unknown")
        self.assertEqual(detect_card_version(None), "unknown")
        self.assertEqual(detect_card_version([]), "unknown")


class TestReport(unittest.TestCase):
    def test_clean_v1_card_needs_nothing(self):
        items = compat_report(load("card_v1_valid.json"))
        self.assertFalse(needs_migration(items), format_report(items))

    def test_v03_card_gets_actionable_checklist(self):
        items = compat_report(load("card_v03.json"))
        self.assertTrue(needs_migration(items))
        text = format_report(items)
        self.assertIn("supportedInterfaces", text)
        self.assertIn("tags", text)
        actions = [i for i in items if i.status == "action"]
        self.assertGreaterEqual(len(actions), 2)
        # every action item must tell the reader what to do
        for item in actions:
            self.assertTrue(len(item.detail) > 20, item)

    def test_missing_protocol_version_flagged(self):
        card = load("card_v1_minimal.json")
        del card["supportedInterfaces"][0]["protocolVersion"]
        items = compat_report(card)
        self.assertTrue(any(i.check == "protocol-version" and i.status == "action"
                            for i in items))

    def test_mixed_legacy_fields_flagged(self):
        card = load("card_v1_minimal.json")
        card["url"] = "https://minimal.example.com/"
        items = compat_report(card)
        self.assertTrue(any(i.check == "legacy-fields" and i.status == "action"
                            for i in items))

    def test_legacy_fetch_path_flagged(self):
        from a2aops.card import FetchInfo
        info = FetchInfo(base_url="https://x.example", resolved_url="https://x.example/.well-known/agent.json",
                         path_used="/.well-known/agent.json", legacy_fallback=True,
                         status=200, elapsed_ms=5)
        items = compat_report(load("card_v03.json"), info)
        disc = [i for i in items if i.check == "discovery-path"][0]
        self.assertEqual(disc.status, "action")
        self.assertIn("agent-card.json", disc.detail)

    def test_schemes_without_requirements_flagged(self):
        card = load("card_v1_valid.json")
        del card["securityRequirements"]
        items = compat_report(card)
        self.assertTrue(any(i.check == "security-model" and i.status == "action"
                            for i in items))


if __name__ == "__main__":
    unittest.main()
