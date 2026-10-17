import hashlib
from pathlib import Path
import tempfile
import unittest

from fingerprint_manager import kde_pam as pam

TEMPLATE = '#%PAM-1.0\nauth requisite pam_faillock.so preauth\n#-auth required pam_fprintd.so\nauth required pam_env.so\n'


class PamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target, self.vendor, self.state = [self.root / name for name in ('target', 'vendor', 'state')]
        self.vendor.write_text(TEMPLATE)

    def enable(self, **kwargs):
        return pam.apply_enable(self.target, self.vendor, self.state, privileged=False, **kwargs)

    def restore(self):
        return pam.restore(self.target, self.state, privileged=False)

    def test_only_comment_is_removed(self):
        self.assertEqual(pam.enable_text(TEMPLATE), TEMPLATE.replace('#-auth', '-auth'))

    def test_active_rule_is_idempotent(self):
        text = TEMPLATE.replace('#-auth', '-auth')
        self.assertEqual(pam.enable_text(text), text)

    def test_preserve_override_and_restore_exactly(self):
        self.target.write_text(TEMPLATE + '# local setting\n')
        original = self.target.read_bytes()
        self.enable()
        self.assertTrue(pam.enabled(self.target.read_text()))
        self.assertTrue((self.state / 'kde-fingerprint.json').exists())
        self.restore()
        self.assertEqual(self.target.read_bytes(), original)

    def test_vendor_only_restore_removes_override(self):
        self.enable()
        self.restore()
        self.assertFalse(self.target.exists())
        self.assertEqual(self.vendor.read_text(), TEMPLATE)

    def test_repeated_enable_does_not_replace_backup(self):
        self.enable()
        before = (self.state / 'kde-fingerprint.json').read_bytes()
        self.enable()
        self.assertEqual((self.state / 'kde-fingerprint.json').read_bytes(), before)

    def test_restore_refuses_external_edits(self):
        self.enable()
        self.target.write_text('auth required pam_deny.so\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.restore()
        self.assertEqual(self.target.read_text(), 'auth required pam_deny.so\n')

    def test_stale_preview_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'preview'):
            self.enable(expected=hashlib.sha256(b'old config').hexdigest())
        self.assertFalse(self.target.exists())

    def test_unsupported_layout_is_not_replaced(self):
        self.target.write_text('auth include custom-auth\n')
        with self.assertRaises(ValueError):
            self.enable()
        self.assertEqual(self.target.read_text(), 'auth include custom-auth\n')

    def test_ambiguous_rules_are_refused(self):
        with self.assertRaises(ValueError):
            pam.enable_text(TEMPLATE + '#auth sufficient pam_fprintd.so\n')

    def test_symlink_target_is_refused(self):
        self.target.symlink_to(self.vendor)
        with self.assertRaises(ValueError):
            self.enable()
        self.assertEqual(self.vendor.read_text(), TEMPLATE)

    def test_symlink_backup_directory_is_refused(self):
        other = self.root / 'other'
        other.mkdir()
        self.state.symlink_to(other)
        with self.assertRaises(ValueError):
            self.enable()

    def test_missing_native_service_is_reported(self):
        self.vendor.unlink()
        self.assertFalse(pam.inspect(self.target, self.vendor, self.state)['supported'])

    def test_bracketed_or_optional_controls_are_not_treated_as_safe(self):
        self.assertFalse(pam.enabled('auth optional pam_fprintd.so\n'))
        with self.assertRaises(ValueError):
            pam.enable_text('#auth [success=done default=ignore] pam_fprintd.so\n')


if __name__ == '__main__':
    unittest.main()
