"""Offline watcher contract tests; no Discord or GitHub access needed."""
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from notifiers import DiscordNotifier, DeliveryError, Event, webhook_url_valid
from watcher import discover, initial_state, load_state, run_cycle, save_state
from verifier import VerificationError


def archive(messages):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for number, text in messages.items():
            base = f"mf-nodeops-comms-main/announcements/mf-{number}/"
            z.writestr(base + "announcement.txt", text)
            z.writestr(base + "announcement.sig", f"sig{number}")
    return out.getvalue()


def fake_verification(number, config, archive_bytes):
    return {"severity": "ORANGE" if number == 3 else "GREEN", "created": "2026-10-16 05:45 UTC", "signers": ["A"*40, "B"*40]}


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.state = initial_state()
        self.events = []
        self.saves = []
        self.send = self.events.append
        self.persist = lambda: self.saves.append(json.dumps(self.state, sort_keys=True))
        self.patch = patch("watcher.verify_announcement", side_effect=fake_verification)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def cycle(self, messages, start_mode="latest"):
        return run_cycle(self.state, archive(messages), {}, self.send, self.persist, start_mode)

    def test_bootstrap_alerts_only_latest(self):
        self.cycle({0: "a", 1: "b"})
        self.assertEqual([(e.number, e.status) for e in self.events], [(1, "VERIFIED")])
        self.assertTrue(self.state["initialized"])
        self.assertEqual(len(self.state["seen"]), 2)

    def test_bootstrap_silent_option(self):
        self.cycle({0: "a", 1: "b"}, "silent")
        self.assertEqual(self.events, [])

    def test_no_duplicates_new_announcement(self):
        self.cycle({1: "a"})
        self.events.clear()
        self.cycle({1: "a", 2: "b"})
        self.assertEqual([(e.number, e.kind) for e in self.events], [(2, "NEW")])
        self.cycle({1: "a", 2: "b"})
        self.assertEqual(len(self.events), 1)

    def test_signed_content_change_triggers_alert(self):
        self.cycle({1: "a"})
        self.events.clear()
        self.cycle({1: "new signed content"})
        self.assertEqual((self.events[0].status, self.events[0].kind), ("VERIFIED", "CHANGED"))

    def test_signature_failure_and_recovery(self):
        self.cycle({1: "a"})
        self.events.clear()
        with patch("watcher.verify_announcement", side_effect=VerificationError("bad signature")):
            self.cycle({1: "altered"})
            self.cycle({1: "altered"})
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0].status, "FAILED")
        self.cycle({1: "altered"})
        self.assertEqual((self.events[-1].status, self.events[-1].kind), ("VERIFIED", "RECOVERED"))

    def test_alert_failures_are_retried_without_ack(self):
        def fail(event):
            raise DeliveryError("503")
        with self.assertRaises(DeliveryError):
            run_cycle(self.state, archive({1: "a"}), {}, fail, self.persist)
        self.assertEqual(self.state["seen"], {})
        self.assertFalse(self.state["initialized"])
        self.cycle({1: "a"})
        self.assertEqual(len(self.events), 1)

    def test_old_delivery_failure_does_not_block_newer_urgent_alert(self):
        self.state["initialized"] = True
        delivered = []
        def mixed(event):
            if event.number == 1:
                raise DeliveryError("simulated failure")
            delivered.append(event.number)
        with self.assertRaises(DeliveryError):
            run_cycle(self.state, archive({1: "old", 2: "new"}), {}, mixed, self.persist)
        self.assertEqual(delivered, [2])
        self.assertNotIn("1", self.state["seen"])
        self.assertIn("2", self.state["seen"])

    def test_state_saved_persistently_and_reloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "state.json"
            save_state(p, self.state)
            self.assertEqual(load_state(p), self.state)
            if os.name != "nt":
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_corrupted_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "state.json"
            p.write_text("{notjson", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                load_state(p)

    def test_discovery_ignores_incomplete_folders(self):
        self.assertEqual(set(discover(archive({0: "a", 4: "b"}))), {0, 4})

    def test_verified_red_is_red_alert(self):
        body = DiscordNotifier.payload(Event(3, "VERIFIED", "NEW", "RED", signers=("A"*40, "B"*40)))
        self.assertIn("CODE RED", body["embeds"][0]["title"])
        self.assertEqual(body["allowed_mentions"], {"parse": []})
        self.assertNotIn("content", body)

    def test_failed_message_is_not_false_success(self):
        body = DiscordNotifier.payload(Event(3, "FAILED", "NEW", reason="bad signature"))
        self.assertIn("FAILED", body["embeds"][0]["title"])
        self.assertNotIn("CODE GREEN", body["embeds"][0]["title"])

    def test_test_alert_is_explicitly_not_signed(self):
        body = DiscordNotifier.payload(Event(0, "TEST", "TEST"))
        self.assertIn("NOT AN ANNOUNCEMENT", body["embeds"][0]["title"])

    def test_reject_non_discord_webhooks(self):
        self.assertFalse(webhook_url_valid("https://example.com/api/webhooks/123/secret"))
        self.assertFalse(webhook_url_valid("http://discord.com/api/webhooks/123/secret"))
        self.assertFalse(webhook_url_valid("https://discord.com.attacker.tld/api/webhooks/123/secret"))
        self.assertFalse(webhook_url_valid("https://discord.com/api/webhooks/123/secret?q=x"))
        self.assertTrue(webhook_url_valid("https://discord.com/api/webhooks/123456/AAA-BBB_cc"))


if __name__ == "__main__":
    unittest.main()
