from pathlib import Path
import tempfile
import unittest

from fingerprint_manager.pam_services import ALLOWED, MARKER, PamStore, locations


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.etc, self.vendor = self.root / 'etc', self.root / 'vendor'
        self.etc.mkdir()
        self.vendor.mkdir()
        self.release = self.root / 'os-release'
        self.release.write_text('ID=endeavouros\nID_LIKE=arch\n')
        self.dm = self.root / 'display-manager.service'
        self.store = PamStore(self.etc, self.vendor, self.root / 'state', self.release, self.dm)
        self.write('system-auth', 'auth required pam_faillock.so preauth\n'
                   'auth [success=1 default=bad] pam_unix.so try_first_pass\n'
                   'auth [default=die] pam_faillock.so authfail\n'
                   'auth optional pam_permit.so\nauth required pam_env.so\n')
        self.write('sudo', '#%PAM-1.0\nauth include system-auth\naccount include system-auth\n')

    def write(self, name, text, vendor=False):
        path = (self.vendor if vendor else self.etc) / name
        path.write_text(text)
        return path

    def enable(self, service='sudo'):
        return self.store.enable(service, self.store.inspect(service)['digest'])

    def test_polkit_location_reads_effective_service(self):
        self.write('polkit-1', 'auth include system-auth\n', vendor=True)
        self.write('polkit-1', 'auth sufficient pam_fprintd.so\nauth include system-auth\n')
        row = next(row for row in locations(self.store, {'XDG_CURRENT_DESKTOP': 'KDE'}) if row['key'] == 'polkit')
        self.assertEqual(row['service'], 'polkit-1')
        self.assertEqual(row['status'], 'external')
        self.assertTrue(row['enabled'])

    def test_include_and_substack_detect_external_rule(self):
        self.write('system-auth', 'auth substack fingerprints\n')
        self.write('fingerprints', 'auth sufficient pam_fprintd.so\n')
        plan = self.store.inspect('sudo')
        self.assertTrue(plan['enabled'])
        self.assertEqual(plan['status'], 'external')
        self.assertIn('fingerprints', plan['detail'])
        self.assertFalse(plan['supported'])

    def test_auth_only_not_account_include(self):
        self.write('sudo', 'account include fingerprint-stack\nauth include system-auth\n')
        self.write('fingerprint-stack', 'auth sufficient pam_fprintd.so\n')
        self.assertFalse(self.store.inspect('sudo')['enabled'])

    def test_at_include(self):
        self.write('sudo', '@include fingerprint-stack\n')
        self.write('fingerprint-stack', 'auth sufficient pam_fprintd.so\n')
        self.assertTrue(self.store.inspect('sudo')['enabled'])

    def test_etc_overrides_vendor(self):
        self.write('sudo', 'auth sufficient pam_fprintd.so\n', vendor=True)
        self.assertFalse(self.store.inspect('sudo')['enabled'])

    def test_cycle_is_unknown_and_uneditable(self):
        self.write('system-auth', 'auth include sudo\n')
        plan = self.store.inspect('sudo')
        self.assertEqual(plan['status'], 'unknown')
        self.assertIn('cycle', plan['detail'])
        self.assertFalse(plan['supported'])

    def test_missing_include_is_not_disabled(self):
        self.write('sudo', 'auth include missing\n')
        self.assertEqual(self.store.inspect('sudo')['status'], 'unknown')

    def test_include_traversal_is_rejected(self):
        self.write('sudo', 'auth include ../../secret\n')
        self.assertFalse(self.store.inspect('sudo')['supported'])

    def test_addition_preserves_inherited_gates_and_original_stack(self):
        original = (self.etc / 'sudo').read_text()
        shared = (self.etc / 'system-auth').read_bytes()
        self.enable()
        text = (self.etc / 'sudo').read_text()
        self.assertLess(text.index('pam_faillock.so preauth'), text.index('pam_fprintd.so'))
        self.assertLess(text.index('pam_env.so'), text.index('pam_fprintd.so'))
        self.assertIn(original.split('\n', 1)[1], text)
        self.assertEqual((self.etc / 'system-auth').read_bytes(), shared)
        self.assertEqual(self.store.inspect('sudo')['status'], 'managed')

    def test_sddm_numeric_jumps_keep_their_original_targets(self):
        auth = 'auth [success=1 default=ignore] pam_unix.so\nauth include system-login\n'
        self.write('sddm', auth)
        self.write('system-login', 'auth required pam_shells.so\nauth requisite pam_nologin.so\nauth include system-auth\n')
        self.enable('sddm')
        text = (self.etc / 'sddm').read_text()
        self.assertTrue(text.endswith(auth))
        self.assertLess(text.index('pam_nologin.so'), text.index('pam_fprintd.so'))

    def test_unknown_mfa_stack_is_never_short_circuited(self):
        self.write('system-auth', 'auth required pam_unix.so\nauth required pam_u2f.so\n')
        plan = self.store.inspect('sudo')
        self.assertFalse(plan['supported'])
        self.assertIn('pam_u2f', plan['detail'])
        with self.assertRaises(ValueError):
            self.enable()

    def test_non_arch_addition_requires_profile(self):
        self.release.write_text('ID=fedora\n')
        self.assertFalse(self.store.inspect('sudo')['supported'])

    def test_native_kde_uncomment_and_restore(self):
        text = '#%PAM-1.0\nauth requisite pam_nologin.so\n#-auth required pam_fprintd.so\n'
        self.write('kde-fingerprint', text)
        self.enable('kde-fingerprint')
        self.assertIn('-auth required pam_fprintd.so', (self.etc / 'kde-fingerprint').read_text())
        plan = self.store.restore_plan('kde-fingerprint')
        self.store.restore('kde-fingerprint', plan['digest'])
        self.assertEqual((self.etc / 'kde-fingerprint').read_text(), text)

    def test_native_sufficient_rule_is_not_uncommented_over_mfa(self):
        self.write('kde-fingerprint', '#auth sufficient pam_fprintd.so\nauth required pam_u2f.so\n')
        self.assertFalse(self.store.inspect('kde-fingerprint')['supported'])

    def test_stale_dependency_prevents_write(self):
        plan = self.store.inspect('sudo')
        original = (self.etc / 'sudo').read_bytes()
        self.write('system-auth', 'auth required pam_unix.so\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.store.enable('sudo', plan['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), original)

    def test_enable_is_idempotent(self):
        self.enable()
        first = (self.etc / 'sudo').read_bytes()
        self.enable()
        self.assertEqual((self.etc / 'sudo').read_bytes(), first)
        self.assertEqual(first.count(b'auth sufficient pam_fprintd.so'), 1)

    def test_restore_refuses_later_edits(self):
        self.enable()
        (self.etc / 'sudo').write_text('# an external edit\n')
        with self.assertRaisesRegex(ValueError, 'edited'):
            self.store.restore_plan('sudo')

    def test_restore_preview_and_exact_original(self):
        original = (self.etc / 'sudo').read_bytes()
        self.enable()
        plan = self.store.restore_plan('sudo')
        self.assertIn('-auth sufficient pam_fprintd.so', plan['preview'])
        self.store.restore('sudo', plan['digest'])
        self.assertEqual((self.etc / 'sudo').read_bytes(), original)

    def test_vendor_override_is_removed_on_restore(self):
        (self.etc / 'sudo').unlink()
        self.write('sudo', 'auth include system-auth\n', vendor=True)
        self.enable()
        plan = self.store.restore_plan('sudo')
        self.assertIn('Remove the app-created override', plan['preview'])
        self.store.restore('sudo', plan['digest'])
        self.assertFalse((self.etc / 'sudo').exists())

    def test_arbitrary_service_cannot_be_written(self):
        for name in ['system-auth', '../../sudo', 'login', 'gdm-password']:
            with self.assertRaises(ValueError):
                self.store.enable(name, 'irrelevant')

    def test_vendor_change_invalidates_restore_preview(self):
        (self.etc / 'sudo').unlink()
        self.write('sudo', 'auth include system-auth\n', vendor=True)
        self.enable()
        plan = self.store.restore_plan('sudo')
        self.write('sudo', '# updated vendor\nauth include system-auth\n', vendor=True)
        with self.assertRaisesRegex(ValueError, 'preview'):
            self.store.restore('sudo', plan['digest'])
        self.assertTrue((self.etc / 'sudo').exists())

    def test_previewing_restore_does_not_mutate_configuration(self):
        self.enable()
        before = (self.etc / 'sudo').read_bytes()
        self.store.restore_plan('sudo')
        self.assertEqual((self.etc / 'sudo').read_bytes(), before)

    def test_empty_expected_digest_cannot_apply(self):
        with self.assertRaisesRegex(ValueError, 'preview'):
            self.store.enable('sudo', None)
        self.assertNotIn(MARKER, (self.etc / 'sudo').read_text())

    def test_active_display_manager_detection_not_first_installed(self):
        self.write('sddm', 'auth include system-auth\n')
        self.write('plasmalogin', 'auth include system-auth\n')
        unit = self.root / 'plasmalogin.service'
        unit.touch()
        self.dm.symlink_to(unit)
        rows = locations(self.store, {'XDG_CURRENT_DESKTOP': 'KDE'})
        self.assertEqual(rows[1]['service'], 'plasmalogin')
        self.assertEqual(rows[2]['service'], 'kde-fingerprint')

    def test_unknown_login_requires_explicit_selection(self):
        self.write('sddm', 'auth include system-auth\n')
        rows = locations(self.store, {'XDG_CURRENT_DESKTOP': 'OTHER'})
        self.assertEqual(rows[1]['service'], '')
        self.assertEqual(rows[1]['choices'], ['sddm'])
        self.assertEqual(rows[2]['status'], 'unknown')

    def test_gnome_lock_uses_dedicated_service(self):
        self.assertEqual(locations(self.store, {'XDG_CURRENT_DESKTOP': 'ubuntu:GNOME'})[2]['service'], 'gdm-fingerprint')

    def test_commented_fingerprint_is_not_detected_as_enabled(self):
        self.write('sudo', '#auth sufficient pam_fprintd.so\nauth include system-auth\n')
        self.assertFalse(self.store.inspect('sudo')['enabled'])


if __name__ == '__main__':
    unittest.main()
