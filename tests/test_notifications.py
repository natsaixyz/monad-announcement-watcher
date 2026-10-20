"""Offline adapter and multi-channel delivery tests."""
import hashlib
import hmac
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from notifiers import (CustomWebhookNotifier, TelegramNotifier, DeliveryError,
                       Event, custom_url_valid)
from watcher import initial_state, run_cycle, load_state, save_state


def archive(messages):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for number, content in messages.items():
            base = f"mf-nodeops-comms-main/announcements/mf-{number}/"
            z.writestr(base + "announcement.txt", content)
            z.writestr(base + "announcement.sig", f"sig{number}")
    return out.getvalue()


def verified(number, config, archive_bytes):
    return {"severity": "RED", "created": "2026-10-16 05:45 UTC", "signers": ["A"*40,"B"*40]}


class FakeResponse:
    status = 204
    def __enter__(self): return self
    def __exit__(self, *args): pass

class FakeOpener:
    def __init__(self):
        self.request = None
    def open(self, request, timeout):
        self.request = request
        return FakeResponse()

class DeliveryTests(unittest.TestCase):
    def test_custom_https_validation(self):
        self.assertTrue(custom_url_valid('https://hooks.example.com/path?key=abc'))
        for url in ('http://hooks.example.com', 'https://localhost/abc',
                    'https://127.0.0.1/x', 'https://10.0.0.1/x',
                    'https://[::1]/', 'https://a.example.com:8080/x',
                    'https://user:pass@hooks.example.com/',
                    'https://hooks.example.com/#secret'):
            with self.subTest(url=url):
                self.assertFalse(custom_url_valid(url))

    def test_custom_json_schema_and_hmac(self):
        opener = FakeOpener()
        with patch('notifiers.urllib.request.build_opener', return_value=opener):
            CustomWebhookNotifier('https://hooks.example.com/verify', 'long-shared-secret-123').send(
                Event(number=3, status='VERIFIED', kind='NEW', severity='RED',
                      signers=('A'*40, 'B'*40), digest='a'*64))
        req = opener.request
        body = req.data
        payload = json.loads(body)
        self.assertEqual(payload['schema_version'], 1)
        self.assertEqual(payload['event_type'], 'monad.announcement.verification')
        self.assertEqual(payload['announcement']['id'], 'mf-3')
        self.assertIsNone(payload['announcement']['severity'])
        self.assertEqual(payload['verification']['scope'], 'signatures_only')
        self.assertFalse(payload['verification']['metadata_checked'])
        self.assertEqual(payload['verification']['status'], 'VERIFIED')
        self.assertEqual(len(payload['verification']['signers']), 2)
        self.assertEqual(payload['event_id'], req.get_header('X-monad-event-id'))
        signature = hmac.new(b'long-shared-secret-123', body, hashlib.sha256).hexdigest()
        self.assertEqual(req.get_header('X-monad-signature'), f'sha256={signature}')

    def test_custom_payload_error_no_severity(self):
        payload = CustomWebhookNotifier.payload(Event(number=2, status='FAILED', kind='CHANGED',
                                                  severity='UNCLASSIFIED', reason='bad signature'))
        self.assertIsNone(payload['announcement']['severity'])
        self.assertEqual(payload['verification']['error'], 'bad signature')

    def test_custom_webhook_redirect_fails_closed(self):
        opener = FakeOpener()
        def fail(req, timeout):
            raise HTTPError(req.full_url, 302, 'Moved', {}, None)
        opener.open = fail
        with patch('notifiers.urllib.request.build_opener', return_value=opener):
            with self.assertRaises(DeliveryError):
                CustomWebhookNotifier('https://hooks.example.com/verify').send(Event(1, 'TEST', 'TEST'))

    def test_custom_secret_short_rejected(self):
        with self.assertRaises(ValueError):
            CustomWebhookNotifier('https://hooks.example.com/verify', 'tiny')

    def test_telegram_plain_text(self):
        msg = TelegramNotifier.message(Event(3, 'VERIFIED', 'NEW', 'RED', signers=('A'*40, 'B'*40)))
        self.assertIn('GPG SIGNATURES VERIFIED', msg)
        self.assertNotIn('CODE RED', msg)
        self.assertIn('Signatures only', msg)
        self.assertIn('mf-3', msg)
        self.assertIn('2 distinct', msg)

    def test_per_destination_delivery_retry_no_duplicate(self):
        state = initial_state()
        events = {'discord': [], 'telegram': [], 'webhook': []}
        fail_first = [True]
        def discord(e): events['discord'].append(e.number)
        def telegram(e):
            if fail_first[0]:
                fail_first[0] = False
                raise DeliveryError('temporary')
            events['telegram'].append(e.number)
        def webhook(e): events['webhook'].append(e.number)
        with tempfile.TemporaryDirectory() as temp, patch('watcher.verify_announcement', side_effect=verified):
            path = Path(temp)/'state.json'
            persist = lambda: save_state(path, state)
            sinks = {'discord': discord, 'telegram': telegram, 'webhook': webhook}
            with self.assertRaises(DeliveryError):
                run_cycle(state, archive({1:'v1'}), {}, sinks, persist)
            self.assertEqual(events, {'discord':[1], 'telegram':[], 'webhook':[1]})
            self.assertTrue(load_state(path)['seen']['1']['pending'])
            # Restart with stored state and retry only failed destination
            new_state = load_state(path)
            run_cycle(new_state, archive({1:'v1'}), {}, sinks, lambda:save_state(path, new_state))
            self.assertEqual(events, {'discord':[1], 'telegram':[1], 'webhook':[1]})
            self.assertFalse(load_state(path)['seen']['1']['pending'])

    def test_new_channel_does_not_replay_old_alerts(self):
        state = initial_state()
        events = {'discord': [], 'telegram': []}
        with patch('watcher.verify_announcement', side_effect=verified):
            run_cycle(state, archive({1:'a'}), {}, {'discord': lambda e: events['discord'].append(e.number)}, lambda: None)
            run_cycle(state, archive({1:'a'}), {}, {'discord': lambda e: events['discord'].append(e.number), 'telegram': lambda e: events['telegram'].append(e.number)}, lambda: None)
            self.assertEqual(events, {'discord':[1], 'telegram':[]})
            run_cycle(state, archive({1:'a', 2:'b'}), {}, {'discord': lambda e: events['discord'].append(e.number), 'telegram': lambda e: events['telegram'].append(e.number)}, lambda: None)
            self.assertEqual(events, {'discord':[1,2], 'telegram':[2]})

if __name__ == '__main__':
    unittest.main()
