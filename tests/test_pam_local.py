import unittest
import test_pam_services as fixtures
from fingerprint_manager.pam_services import PamStore
import base64
import json


class LocalConfigurationTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    write = fixtures.ServiceTests.write
    def apply_local(self, action, service='sudo'):
        with self.store.locked():
            plan = self.store.local_plan(service, action)
        return self.store.set_local(service, action, plan['digest'])

    def test_local_toggle_without_takeover_and_restore(self):
        original = (self.etc / 'sudo').read_bytes()
        self.assertEqual(self.store.inspect('sudo')['origin'], 'local')
        self.apply_local('local-enable')
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.apply_local('local-disable')
        self.assertFalse(self.store.inspect('sudo')['enabled'])
        self.apply_local('local-enable')
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.assertEqual(len(list((self.store.state / 'history').glob('*.json'))), 3)
        self.store.restore('sudo', self.store.restore_plan('sudo')['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), original)

    def test_existing_fingerprint_can_be_disabled_without_takeover(self):
        self.write('sudo', 'auth sufficient pam_fprintd.so\nauth include system-auth\n')
        original = (self.etc / 'sudo').read_bytes()
        shared = (self.etc / 'system-auth').read_bytes()
        self.apply_local('local-disable')
        self.assertFalse(self.store.inspect('sudo')['enabled'])
        self.assertEqual((self.etc / 'system-auth').read_bytes(), shared)
        self.apply_local('local-enable')
        self.assertEqual((self.etc / 'sudo').read_bytes(), original)

    def test_vendor_is_read_only_until_override_is_created(self):
        original = (self.etc / 'sudo').read_bytes()
        (self.etc / 'sudo').unlink()
        self.write('sudo', original.decode(), vendor=True)
        self.assertEqual(self.store.inspect('sudo')['origin'], 'vendor')
        with self.assertRaisesRegex(ValueError, 'read-only'):
            self.store.local_plan('sudo', 'local-enable')
        self.apply_local('create-override')
        self.assertEqual((self.vendor / 'sudo').read_bytes(), original)
        self.assertEqual(self.store.inspect('sudo')['origin'], 'local')
        self.store.restore('sudo', self.store.restore_plan('sudo')['digest'])
        self.assertFalse((self.etc / 'sudo').exists())

    def test_inherited_disable_does_not_edit_shared_files(self):
        self.write('system-auth', 'auth sufficient pam_fprintd.so\nauth required pam_unix.so\n')
        shared = (self.etc / 'system-auth').read_bytes()
        self.apply_local('local-disable')
        self.assertFalse(self.store.inspect('sudo')['enabled'])
        self.assertEqual((self.etc / 'system-auth').read_bytes(), shared)
        self.apply_local('local-enable')
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.assertEqual((self.etc / 'system-auth').read_bytes(), shared)

    def test_later_local_edits_are_kept_and_become_new_backup_baseline(self):
        self.apply_local('local-enable')
        with (self.etc / 'sudo').open('a') as stream:
            stream.write('# later administrator edit\n')
        edited = (self.etc / 'sudo').read_bytes()
        self.apply_local('local-disable')
        self.assertIn(b'# later administrator edit', (self.etc / 'sudo').read_bytes())
        self.store.restore('sudo', self.store.restore_plan('sudo')['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), edited)

    def test_changed_preview_refuses_write(self):
        plan = self.store.local_plan('sudo', 'local-enable')
        with (self.etc / 'sudo').open('a') as stream:
            stream.write('# concurrent change\n')
        edited = (self.etc / 'sudo').read_bytes()
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.store.set_local('sudo', 'local-enable', plan['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), edited)

    def test_legacy_takeover_backup_still_restores(self):
        original = (self.etc / 'sudo').read_bytes()
        self.store.adopt('sudo', self.store.adopt_plan('sudo')['digest'])
        self.apply_local('local-enable')
        self.store.restore('sudo', self.store.restore_plan('sudo')['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), original)

    def test_restore_refuses_later_edits(self):
        self.apply_local('local-enable')
        with (self.etc / 'sudo').open('a') as stream:
            stream.write('# later edit\n')
        with self.assertRaisesRegex(ValueError, 'edited after'):
            self.store.restore_plan('sudo')

    def test_failed_override_write_keeps_vendor_and_removes_partial_record(self):
        from unittest.mock import patch
        from fingerprint_manager import pam_services
        original = (self.etc / 'sudo').read_bytes()
        (self.etc / 'sudo').unlink()
        self.write('sudo', original.decode(), vendor=True)
        plan = self.store.local_plan('sudo', 'create-override')
        real_write = pam_services.atomic_write
        def fail_target(path, *args):
            if path == self.etc / 'sudo':
                raise OSError('simulated write failure')
            return real_write(path, *args)
        with patch.object(pam_services, 'atomic_write', side_effect=fail_target):
            with self.assertRaisesRegex(OSError, 'simulated'):
                self.store.set_local('sudo', 'create-override', plan['digest'])
        self.assertFalse((self.etc / 'sudo').exists())
        self.assertFalse((self.store.state / 'sudo.json').exists())
        self.assertEqual((self.vendor / 'sudo').read_bytes(), original)

    def test_authorized_local_preview_can_cancel_or_apply_without_takeover(self):
        import io
        import tempfile
        from fingerprint_manager.pam_services import interactive_review, PREVIEW_PREFIX
        self.write('sudo', 'auth sufficient pam_fprintd.so\nauth include system-auth\n')
        digest = self.store.local_plan('sudo', 'local-disable')['digest']
        before = (self.etc / 'sudo').read_bytes()
        for confirm in (False, True):
            output = io.StringIO()
            with tempfile.TemporaryFile() as stream:
                stream.write((json.dumps(dict(confirm=confirm, expected=digest)) + '\n').encode())
                stream.seek(0)
                interactive_review(self.store, 'sudo', 'local-disable', stream, output)
            self.assertEqual(output.getvalue().count(PREVIEW_PREFIX), 1)
            if not confirm:
                self.assertEqual((self.etc / 'sudo').read_bytes(), before)
                self.assertFalse((self.store.state / 'sudo.json').exists())
        self.assertFalse(self.store.inspect('sudo')['enabled'])

    def test_simple_sufficient_rule_is_commented_and_reenabled_exactly(self):
        original = 'auth\tsufficient\tpam_fprintd.so timeout=10\nauth include system-auth\n'
        self.write('sudo', original)
        self.apply_local('local-disable')
        disabled = (self.etc / 'sudo').read_text()
        self.assertIn('# Fingerprint Manager: disabled: auth\tsufficient\tpam_fprintd.so timeout=10', disabled)
        self.assertNotIn('pam_deny.so', disabled)
        self.assertFalse(self.store.inspect('sudo')['enabled'])
        self.apply_local('local-enable')
        self.assertEqual((self.etc / 'sudo').read_text(), original)

    def test_numeric_jump_stack_keeps_fingerprint_rule_slot(self):
        self.write('sudo', 'auth [success=1 default=ignore] pam_unix.so\n'
                   'auth sufficient pam_fprintd.so\nauth required pam_unix.so\n')
        self.apply_local('local-disable')
        disabled = (self.etc / 'sudo').read_text()
        self.assertIn('auth sufficient pam_deny.so', disabled)
        self.assertIn('auth [success=1 default=ignore] pam_unix.so', disabled)
