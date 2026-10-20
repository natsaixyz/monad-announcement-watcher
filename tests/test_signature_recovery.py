"""Previously failed metadata is rechecked without resetting delivery history."""
import io
import unittest
import zipfile
from unittest.mock import patch
from watcher import discover, run_cycle


class SignatureOnlyRecoveryTests(unittest.TestCase):
    def test_previous_failed_mf3_recovers_once_on_all_destinations(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for number in (1, 2, 3):
                root = f"mf-nodeops-comms-main/announcements/mf-{number}/"
                z.writestr(root + "announcement.txt", f"Announcement #{number}\n")
                z.writestr(root + "announcement.sig", f"signature-{number}")
        archive = buf.getvalue()
        hashes = discover(archive)
        state = {"version": 1, "initialized": True, "seen": {
            str(n): {"digest": digest, "status": "FAILED" if n == 3 else "VERIFIED"}
            for n, digest in hashes.items()
        }}
        events = {"discord": [], "telegram": [], "webhook": []}
        sinks = {name: out.append for name, out in events.items()}
        result = {"severity": "UNCLASSIFIED", "created": "", "signers": ["A"*40, "B"*40]}
        with patch("watcher.verify_announcement", return_value=result) as verify:
            run_cycle(state, archive, {}, sinks, lambda: None)
            run_cycle(state, archive, {}, sinks, lambda: None)
            verify.assert_called_once()
            self.assertEqual(verify.call_args.args[0], 3)
        for out in events.values():
            self.assertEqual([(e.number, e.kind, e.status) for e in out], [(3, "RECOVERED", "VERIFIED")])
        self.assertEqual(set(state["seen"]), {"1", "2", "3"})
        self.assertFalse(state["seen"]["3"]["pending"])
