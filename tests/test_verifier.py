"""Offline cryptographic tests using temporary signing keys (no Monad keys or network)."""
from __future__ import annotations

import hashlib
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

    def test_display_does_not_parse_header_or_dates(self):
        content = b'Announcement #3\nCreated: not-an-ISO-date\nCODE RED\nCODE GREEN\n'
        display = inspect_announcement(content, 3)
        self.assertEqual(display['message'], content.decode())
        self.assertEqual(display['number'], 3)
        self.assertEqual(display['created'], '')
        self.assertIsNone(display['expires'])
        self.assertEqual(display['severity'], 'UNCLASSIFIED')

    def test_display_never_claims_signature_success(self):
        self.assertNotIn('ok', inspect_announcement(b'arbitrary unverified data', 3))

    def test_display_invalid_utf8_does_not_mutate_original(self):
        content = b'\xffunusual text'
        self.assertIn('unusual text', inspect_announcement(content, 3)['message'])
        self.assertEqual(content, b'\xffunusual text')

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

    def fixture_zip(self, message: bytes, signature: bytes, keys: list[bytes] | None = None, number: int = 1) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            prefix = 'mf-nodeops-comms-main/'
            archive.writestr(prefix + f'announcements/mf-{number}/announcement.txt', message)
            archive.writestr(prefix + f'announcements/mf-{number}/announcement.sig', signature)
            for index, key in enumerate(keys if keys is not None else self.keys):
                archive.writestr(prefix + f'keys/signer-{index}.pub.asc', key)
        return output.getvalue()

    def test_two_distinct_signers_pass(self):
        signature = self.sign(self.message)
        verified = verify_announcement(1, self.config, self.fixture_zip(self.message, signature))
        self.assertTrue(verified['ok'])
        self.assertEqual(set(verified['signers']), set(self.fps[:2]))
        self.assertEqual(verified['severity'], 'UNCLASSIFIED')
        self.assertEqual(verified['verification_scope'], 'signatures_only')
        self.assertFalse(verified['metadata_checked'])


    def test_mf3_header_regression_real_gpg(self):
        # Reproduces the supplied header; uses local test keys, not Monad's signatures.
        content = b'Announcement #3\n\nCreated: 2026-09-09T05:06:00Z\n\nLocal test fixture.\n'
        sig = self.sign(content)
        result = verify_announcement(3, self.config, self.fixture_zip(content, sig, number=3))
        self.assertTrue(result['ok'])
        self.assertEqual(result['message'], content.decode())
        self.assertEqual(result['message_sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(result['number_source'], 'repository_folder')

    def test_body_format_does_not_decide_signature_validity(self):
        contents = [
            b'No announcement heading or dates.\n',
            b'Announcement #99\nCreated: not a date\n',
            b'MF Announcement #1\nCreated: 2999-01-01T00:00:00Z\n',
            b'Expires: 2000-01-01T00:00:00Z\nCODE RED\nCODE GREEN\n',
            b'Created: one\nCreated: two\n\xffUnusual encoding\n',
        ]
        for content in contents:
            with self.subTest(content=content):
                sig = self.sign(content)
                result = verify_announcement(1, self.config, self.fixture_zip(content, sig))
                self.assertTrue(result['ok'])
                self.assertFalse(result['metadata_checked'])
                self.assertIn('Signatures only', result['notice'])

    def test_bare_heading_tampering_still_fails(self):
        content = b'Announcement #3\nUnparsed content.\n'
        sig = self.sign(content)
        with self.assertRaises(VerificationError):
            verify_announcement(3, self.config, self.fixture_zip(content + b'TAMPERED', sig, number=3))

    def test_gpg_runs_before_display(self):
        from unittest.mock import patch
        content = b'Announcement #3\n'
        with patch('verifier.verify_signatures', side_effect=VerificationError('bad signature')):
            with patch('verifier.inspect_announcement') as display:
                with self.assertRaises(VerificationError):
                    verify_announcement(3, self.config, self.fixture_zip(content, b'bad', number=3))
                display.assert_not_called()

    def test_expired_revoked_and_invalid_gpg_statuses_still_fail(self):
        from unittest.mock import patch
        import verifier
        real_gpg = verifier._gpg
        for status in ('BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPSIG', 'EXPKEYSIG',
                       'REVKEYSIG', 'KEYREVOKED', 'KEYEXPIRED', 'SIGEXPIRED', 'FAILURE', 'ERROR'):
            with self.subTest(status=status):
                def fake_gpg(args, home, timeout=12):
                    if '--verify' in args:
                        return subprocess.CompletedProcess(args, 0, '[GNUPG:] ' + status + ' test\n', '')
                    return real_gpg(args, home, timeout)
                with patch('verifier._gpg', side_effect=fake_gpg):
                    with self.assertRaises(VerificationError):
                        verify_signatures(self.message, b'dummy', self.keys, self.config)

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
