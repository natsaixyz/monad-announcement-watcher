"""Offline cryptographic tests using temporary signing keys (no Monad keys or network)."""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from verifier import (
    VerificationError, inspect_announcement, load_config, parse_number,
    repository_files, latest_announcement_number, verify_announcement, verify_signatures,
)


def cmd(home, *args):
    result = subprocess.run(["gpg", "--homedir", str(home), "--batch", "--no-tty", "--yes", *args],
                            capture_output=True, text=True, check=False, timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout


class ParsingTests(unittest.TestCase):
    def test_valid_paths(self):
        for value in (
            '1', 'mf-1', 'MF-1',
            'https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-1',
            'https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-1/',
            'https://github.com/monad-crypto/mf-nodeops-comms/blob/main/announcements/mf-1/announcement.txt',
        ):
            with self.subTest(value=value):
                self.assertEqual(1, parse_number(value))

    def test_unsafe_links_rejected(self):
        for value in (
            'http://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-1',
            'https://github.com.evil.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-1',
            'https://github.com/monad-crypto/another-repo/tree/main/announcements/mf-1',
            'https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-1/../../keys',
            'https://evil.example/foo',
            'https://github.com@evil.example/foo',
            'https://github.com/monad-crypto/mf-nodeops-comms/tree/main/announcements/mf-1?foo=bar',
            'mf-999999999999999',
            '1; rm -rf /',
        ):
            with self.subTest(value=value), self.assertRaises(VerificationError):
                parse_number(value)

    def test_index_and_utc_timestamp(self):
        content = b'MF Announcement #1\n\nCreated: 2026-10-16T05:45:00UTC\n\nCODE GREEN: TEST\n'
        self.assertEqual(inspect_announcement(content, 1)['severity'], 'GREEN')
        with self.assertRaises(VerificationError):
            inspect_announcement(content, 2)

    def test_future_timestamp_rejected(self):
        future = (datetime.now(timezone.utc) + timedelta(days=3)).strftime('%Y-%m-%dT%H:%M:%SZ')
        with self.assertRaisesRegex(VerificationError, 'future'):
            inspect_announcement(f'MF Announcement #1\nCreated: {future}\n'.encode(), 1)

    def test_expired_timestamp_rejected(self):
        content = b'MF Announcement #1\nCreated: 2026-01-01T01:00:00Z\nExpires: 2026-01-02T01:00:00Z\n'
        with self.assertRaisesRegex(VerificationError, 'expired'):
            inspect_announcement(content, 1)

    def test_conflicting_severities_rejected(self):
        content = b'MF Announcement #1\nCreated: 2026-01-01T01:00:00Z\nCODE RED\nCODE GREEN\n'
        with self.assertRaisesRegex(VerificationError, 'conflicting'):
            inspect_announcement(content, 1)

    def test_config_fingerprints_are_pinned(self):
        config = load_config(Path(__file__).resolve().parent.parent / 'config.json')
        self.assertEqual(len(config['trusted_fingerprints']), 5)
        self.assertEqual(config['required_signatures'], 2)


class LatestNumberTests(unittest.TestCase):
    def fixture_zip(self, paths):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, 'w') as archive:
            for path in paths:
                archive.writestr('mf-nodeops-comms-main/' + path, b'contents')
        return bio.getvalue()

    def test_highest_complete_number(self):
        archive = self.fixture_zip([
            'announcements/mf-0/announcement.txt', 'announcements/mf-0/announcement.sig',
            'announcements/mf-7/announcement.txt', 'announcements/mf-7/announcement.sig',
            'announcements/mf-8/announcement.txt',  # Not published as a signed pair yet
            'announcements/mf-99/notes.txt',
        ])
        self.assertEqual(latest_announcement_number(archive), 7)

    def test_no_complete_pair(self):
        archive = self.fixture_zip(['announcements/mf-8/announcement.txt'])
        with self.assertRaises(VerificationError):
            latest_announcement_number(archive)

    def test_malformed_zip(self):
        with self.assertRaises(VerificationError):
            latest_announcement_number(b'not a zip')


class GPGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='natsai-gpg-tests-')
        cls.root = Path(cls.tmp.name)
        home = cls.root / 'signers'
        home.mkdir(mode=0o700)
        cls.home = home
        cls.fps = []
        cls.keys = []
        for index in range(3):
            uid = f'Natsai Test Signer {index} <test{index}@example.invalid>'
            cmd(home, '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', uid, 'ed25519', 'sign', '0')
            output = cmd(home, '--with-colons', '--fingerprint', '--list-keys', uid)
            fpr = [line.split(':')[9] for line in output.splitlines() if line.startswith('fpr:')][0]
            cls.fps.append(fpr)
            file = cls.root / f'signer-{index}.pub.asc'
            file.write_text(cmd(home, '--armor', '--export', fpr))
            cls.keys.append(file.read_bytes())
        cls.config = {'trusted_fingerprints': frozenset(cls.fps[:2]), 'required_signatures': 2}
        now = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        cls.message = f'MF Announcement #1\n\nCreated: {now}\n\nCODE GREEN: TEST\n\nThis is an offline test.\n'.encode()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def sign(self, message: bytes, signer_indices=(0, 1)) -> bytes:
        src = self.root / 'message-for-signing.txt'
        src.write_bytes(message)
        combined = b''
        for index in signer_indices:
            dest = self.root / f'sign-{index}.sig'
            cmd(self.home, '--local-user', self.fps[index], '--detach-sign', '--output', str(dest), str(src))
            combined += dest.read_bytes()
        return combined

    def fixture_zip(self, message: bytes, signature: bytes, keys: list[bytes] | None = None) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            prefix = 'mf-nodeops-comms-main/'
            archive.writestr(prefix + 'announcements/mf-1/announcement.txt', message)
            archive.writestr(prefix + 'announcements/mf-1/announcement.sig', signature)
            for index, key in enumerate(keys if keys is not None else self.keys):
                archive.writestr(prefix + f'keys/signer-{index}.pub.asc', key)
        return output.getvalue()

    def test_two_distinct_signers_pass(self):
        signature = self.sign(self.message)
        verified = verify_announcement(1, self.config, self.fixture_zip(self.message, signature))
        self.assertTrue(verified['ok'])
        self.assertEqual(set(verified['signers']), set(self.fps[:2]))
        self.assertEqual(verified['severity'], 'GREEN')

    def test_duplicate_signer_is_not_two(self):
        signature = self.sign(self.message, (0, 0))
        with self.assertRaisesRegex(VerificationError, 'distinct'):
            verify_signatures(self.message, signature, self.keys, self.config)

    def test_one_signature_fails(self):
        signature = self.sign(self.message, (0,))
        with self.assertRaisesRegex(VerificationError, 'distinct'):
            verify_signatures(self.message, signature, self.keys, self.config)

    def test_tampering_fails(self):
        signature = self.sign(self.message)
        changed = self.message.replace(b'offline test', b'hacked change')
        with self.assertRaises(VerificationError):
            verify_signatures(changed, signature, self.keys, self.config)

    def test_unapproved_signer_fails(self):
        signature = self.sign(self.message, (0, 2))
        with self.assertRaises(VerificationError):
            verify_signatures(self.message, signature, self.keys, self.config)

    def test_signing_keys_are_public_only(self):
        self.assertIn(b'BEGIN PGP PUBLIC KEY BLOCK', self.keys[0])
        self.assertNotIn(b'PRIVATE KEY', self.keys[0])

    def test_missing_files_fail_closed(self):
        with self.assertRaisesRegex(VerificationError, 'Missing'):
            repository_files(self.fixture_zip(self.message, b'', []), 2)


if __name__ == '__main__':
    unittest.main()
