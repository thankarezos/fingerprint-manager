import io
import json
import os
import tempfile
import unittest

import test_pam_services as fixtures
from fingerprint_manager.pam_services import interactive_review, PREVIEW_PREFIX


class SessionTests(unittest.TestCase):
    write = fixtures.ServiceTests.write

    def setUp(self):
        fixtures.ServiceTests.setUp(self)
        self.original = 'auth sufficient pam_fprintd.so\nauth include system-auth\n'
        self.write('sudo', self.original)
        self.store.adopt('sudo', self.store.adopt_plan('sudo')['digest'])

    def review(self, answer, action='restore'):
        output = io.StringIO()
        with tempfile.TemporaryFile() as stream:
            if answer is not None:
                stream.write((json.dumps(answer) + '\n').encode())
                stream.seek(0)
            result = interactive_review(self.store, 'sudo', action, stream, output, timeout=1)
        return result, output.getvalue()

    def test_confirmed_preview_applies_same_action(self):
        digest = self.store.restore_plan('sudo')['digest']
        result, output = self.review(dict(confirm=True, expected=digest))
        self.assertIn('restored', result)
        self.assertEqual(output.count(PREVIEW_PREFIX), 1)
        self.assertEqual((self.etc / 'sudo').read_text(), self.original)

    def test_cancel_and_disconnect_make_no_changes(self):
        before = (self.etc / 'sudo').read_bytes()
        for answer in (dict(confirm=False), None):
            result, _ = self.review(answer)
            self.assertIn('cancelled', result)
            self.assertEqual((self.etc / 'sudo').read_bytes(), before)

    def test_mismatched_confirmation_is_rejected(self):
        before = (self.etc / 'sudo').read_bytes()
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.review(dict(confirm=True, expected='wrong'))
        self.assertEqual((self.etc / 'sudo').read_bytes(), before)

    def test_one_authorized_session_can_disable(self):
        digest = self.store.managed_plan('sudo', 'disable')['digest']
        self.review(dict(confirm=True, expected=digest), action='disable')
        self.assertFalse(self.store.inspect('sudo')['enabled'])

    def test_partial_confirmation_expires_without_blocking(self):
        before = (self.etc / 'sudo').read_bytes()
        read, write = os.pipe()
        try:
            os.write(write, b'{')
            with os.fdopen(read, 'rb', buffering=0) as stream:
                with self.assertRaisesRegex(ValueError, 'expired'):
                    interactive_review(self.store, 'sudo', 'restore', stream, io.StringIO(), timeout=0.02)
        finally:
            os.close(write)
        self.assertEqual((self.etc / 'sudo').read_bytes(), before)

    def test_non_object_confirmation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Invalid confirmation'):
            self.review([True])
