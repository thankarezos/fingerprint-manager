import json
import unittest
from unittest.mock import patch

import test_pam_services as fixtures
from fingerprint_manager.pam_services import MARKER
from fingerprint_manager import pam_services


class OwnershipTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    write = fixtures.ServiceTests.write

    def adopt(self, service='sudo'):
        plan = self.store.adopt_plan(service)
        self.store.adopt(service, plan['digest'])

    def toggle(self, action, service='sudo'):
        plan = self.store.managed_plan(service, action)
        self.store.set_managed(service, action, plan['digest'])

    def return_external(self, service='sudo'):
        plan = self.store.restore_plan(service)
        self.store.restore(service, plan['digest'])

    def test_polkit_management_is_independent_of_sudo(self):
        original = 'auth sufficient pam_fprintd.so\nauth include system-auth\n'
        self.write('sudo', original)
        self.write('polkit-1', original)
        self.adopt('polkit-1')
        self.toggle('disable', 'polkit-1')
        self.assertFalse(self.store.inspect('polkit-1')['enabled'])
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.toggle('enable-managed', 'polkit-1')
        self.assertTrue(self.store.inspect('polkit-1')['enabled'])
        self.return_external('polkit-1')
        self.assertEqual((self.etc / 'polkit-1').read_text(), original)

    def test_adopt_preserves_external_authentication(self):
        self.write('sudo', 'auth sufficient pam_fprintd.so\nauth include system-auth\n')
        original = (self.etc / 'sudo').read_text()
        self.adopt()
        self.assertEqual((self.etc / 'sudo').read_text(), MARKER + '\n' + original)
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.return_external()
        self.assertEqual((self.etc / 'sudo').read_text(), original)

    def test_direct_toggle_preserves_shared_stack(self):
        self.write('sudo', 'auth sufficient pam_fprintd.so\nauth include system-auth\n')
        shared = (self.etc / 'system-auth').read_bytes()
        self.adopt()
        self.toggle('disable')
        self.assertFalse(self.store.inspect('sudo')['enabled'])
        self.assertEqual(self.store.inspect('sudo')['status'], 'managed')
        self.assertFalse(list(self.etc.glob('fingerprint-manager-*')))
        self.toggle('enable-managed')
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.assertEqual((self.etc / 'system-auth').read_bytes(), shared)

    def test_inherited_toggle_is_isolated_and_reversible_repeatedly(self):
        shared = (self.etc / 'system-auth').read_text()
        self.write('system-auth', 'auth sufficient pam_fprintd.so\n' + shared)
        self.write('sddm', 'auth include system-auth\n')
        baseline = (self.etc / 'sudo').read_bytes()
        shared = (self.etc / 'system-auth').read_bytes()
        self.adopt()
        for _ in range(3):
            self.toggle('disable')
            self.assertFalse(self.store.inspect('sudo')['enabled'])
            self.assertTrue(self.store.inspect('sddm')['enabled'])
            self.assertEqual((self.etc / 'system-auth').read_bytes(), shared)
            self.assertEqual(len(list(self.etc.glob('fingerprint-manager-*'))), 1)
            self.toggle('enable-managed')
            self.assertTrue(self.store.inspect('sudo')['enabled'])
            self.assertEqual(len(list(self.etc.glob('fingerprint-manager-*'))), 1)
        self.return_external()
        self.assertEqual((self.etc / 'sudo').read_bytes(), baseline)
        self.assertFalse(list(self.etc.glob('fingerprint-manager-*')))

    def test_substack_boundaries_and_numeric_jumps_are_preserved(self):
        self.write('sudo', 'auth [success=1 default=ignore] pam_unix.so\nauth substack fingerprints\nauth include system-auth\n')
        self.write('fingerprints', 'auth sufficient pam_fprintd.so\n')
        self.adopt()
        self.toggle('disable')
        text = (self.etc / 'sudo').read_text()
        self.assertIn('auth [success=1 default=ignore] pam_unix.so', text)
        self.assertIn('auth substack fingerprint-manager-', text)
        self.assertEqual(len([line for line in text.splitlines() if line.startswith('auth')]), 3)

    def test_adopt_disabled_then_enable_and_disable(self):
        original = (self.etc / 'sudo').read_bytes()
        self.adopt()
        self.toggle('enable-managed')
        self.assertTrue(self.store.inspect('sudo')['enabled'])
        self.toggle('disable')
        self.assertFalse(self.store.inspect('sudo')['enabled'])
        self.return_external()
        self.assertEqual((self.etc / 'sudo').read_bytes(), original)

    def test_native_kde_can_be_disabled_without_editing_password_service(self):
        self.write('kde-fingerprint', 'auth requisite pam_nologin.so\nauth required pam_fprintd.so\n')
        password = self.write('kde', 'auth include system-auth\n').read_bytes()
        self.adopt('kde-fingerprint')
        self.toggle('disable', 'kde-fingerprint')
        self.assertIn('auth required pam_deny.so', (self.etc / 'kde-fingerprint').read_text())
        self.assertEqual((self.etc / 'kde').read_bytes(), password)
        self.toggle('enable-managed', 'kde-fingerprint')
        self.assertTrue(self.store.inspect('kde-fingerprint')['enabled'])

    def test_required_fingerprint_in_mixed_stack_is_not_disabled(self):
        self.write('sudo', 'auth required pam_fprintd.so\nauth include system-auth\n')
        self.adopt()
        before = (self.etc / 'sudo').read_bytes()
        with self.assertRaisesRegex(ValueError, 'not safe'):
            self.toggle('disable')
        self.assertEqual((self.etc / 'sudo').read_bytes(), before)

    def test_fingerprint_only_sudo_is_not_disabled(self):
        self.write('sudo', 'auth sufficient pam_fprintd.so\n')
        self.adopt()
        with self.assertRaisesRegex(ValueError, 'password fallback'):
            self.toggle('disable')

    def test_stale_adoption_is_refused(self):
        plan = self.store.adopt_plan('sudo')
        self.write('system-auth', 'auth required pam_unix.so\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.store.adopt('sudo', plan['digest'])
        self.assertNotIn(MARKER, (self.etc / 'sudo').read_text())

    def test_external_edits_block_toggle_and_release(self):
        self.adopt()
        (self.etc / 'sudo').write_text('auth sufficient pam_fprintd.so\n')
        with self.assertRaisesRegex(ValueError, 'externally'):
            self.toggle('disable')
        with self.assertRaises(ValueError):
            self.return_external()

    def test_clone_edits_block_cleanup(self):
        self.write('system-auth', 'auth sufficient pam_fprintd.so\nauth required pam_unix.so\n')
        self.adopt()
        self.toggle('disable')
        clone = next(self.etc.glob('fingerprint-manager-*'))
        clone.write_text('# external edit\n')
        with self.assertRaisesRegex(ValueError, 'edited externally'):
            self.return_external()
        self.assertTrue(clone.exists())

    def test_adopt_vendor_service_releases_override(self):
        (self.etc / 'sudo').unlink()
        self.write('sudo', 'auth include system-auth\n', vendor=True)
        self.adopt()
        self.assertTrue((self.etc / 'sudo').exists())
        self.return_external()
        self.assertFalse((self.etc / 'sudo').exists())

    def test_failed_top_level_write_keeps_previous_configuration(self):
        self.write('system-auth', 'auth sufficient pam_fprintd.so\nauth required pam_unix.so\n')
        self.adopt()
        before = (self.etc / 'sudo').read_bytes()
        record_before = (self.store.state / 'sudo.json').read_bytes()
        plan = self.store.managed_plan('sudo', 'disable')
        write = pam_services.atomic_write
        failed = False
        def fail_once(path, raw, mode):
            nonlocal failed
            if path == self.etc / 'sudo' and not failed:
                failed = True
                raise OSError('fixture write failure')
            return write(path, raw, mode)
        with patch.object(pam_services, 'atomic_write', side_effect=fail_once):
            with self.assertRaises(OSError):
                self.store.set_managed('sudo', 'disable', plan['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), before)
        self.assertEqual((self.store.state / 'sudo.json').read_bytes(), record_before)
        self.assertFalse(list(self.etc.glob('fingerprint-manager-*')))


if __name__ == '__main__':
    unittest.main()
