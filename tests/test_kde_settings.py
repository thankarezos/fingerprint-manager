import base64
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import os

from fingerprint_manager import kde_settings as settings


class KdeSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'kscreenlockerrc'
        self.environment = {'XDG_CURRENT_DESKTOP': 'KDE', 'XDG_CONFIG_HOME': str(self.root)}

    def inspect(self, version='6.8.0', value='false'):
        responses = [SimpleNamespace(stdout='plasmashell ' + version), SimpleNamespace(stdout=value)]
        with patch.object(settings.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name), \
             patch.object(settings.subprocess, 'run', side_effect=responses):
            return settings.inspect(self.environment)

    def test_68_opt_in_is_detected(self):
        result = self.inspect()
        self.assertTrue(result['available'])
        self.assertFalse(result['enabled'])
        self.assertIn('--group Authenticators --key Fingerprint true', result['preview'])

    def test_already_enabled_is_detected(self):
        self.assertTrue(self.inspect(value='true')['enabled'])

    def test_older_plasma_is_not_modified(self):
        self.assertFalse(self.inspect(version='6.7.5')['available'])

    def test_gnome_does_not_probe_kde_tools(self):
        with patch.object(settings.subprocess, 'run') as run:
            self.assertFalse(settings.inspect({'XDG_CURRENT_DESKTOP': 'GNOME'})['available'])
            run.assert_not_called()

    def test_backup_preserves_original_bytes(self):
        original = b'[Greeter]\nTheme=org.kde.breeze.desktop\n[Authenticators]\nFingerprint=false\n'
        self.path.write_bytes(original)
        digest = settings.snapshot(self.path)[2]
        record = settings.backup(digest, self.path, self.root / 'backups')
        payload = json.loads(Path(record).read_text())
        self.assertEqual(base64.b64decode(payload['original']), original)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(Path(record).stat().st_mode & 0o777, 0o600)

    def test_stale_preview_does_not_create_backup_or_change_file(self):
        digest = settings.snapshot(self.path)[2]
        self.path.write_text('[Authenticators]\nFingerprint=false\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            settings.backup(digest, self.path, self.root / 'backups')
        self.assertFalse((self.root / 'backups').exists())

    def test_symlink_config_is_refused(self):
        destination = self.root / 'other'
        destination.touch()
        self.path.symlink_to(destination)
        with self.assertRaises(ValueError):
            settings.snapshot(self.path)

    @unittest.skipUnless(shutil.which('kwriteconfig6') and shutil.which('kreadconfig6'), 'KDE configuration tools required')
    def test_real_command_only_changes_temporary_preference(self):
        self.path.write_text('[Greeter]\nTheme=unchanged\n')
        subprocess.run(['kwriteconfig6', '--file', str(self.path), '--group', 'Authenticators',
                        '--key', 'Fingerprint', 'true'], check=True, timeout=5)
        result = subprocess.run(['kreadconfig6', '--file', str(self.path), '--group', 'Authenticators',
                                 '--key', 'Fingerprint'], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(result.stdout.strip(), 'true')
        self.assertIn('Theme=unchanged', self.path.read_text())
        subprocess.run(['kwriteconfig6', '--file', str(self.path), '--group', 'Authenticators',
                        '--key', 'Fingerprint', 'false'], check=True, timeout=5)
        result = subprocess.run(['kreadconfig6', '--file', str(self.path), '--group', 'Authenticators',
                                 '--key', 'Fingerprint'], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(result.stdout.strip(), 'false')
        self.assertIn('Theme=unchanged', self.path.read_text())

    def apply_fixture(self, enable=False):
        environment = {'XDG_CONFIG_HOME': str(self.root / 'config'),
                       'XDG_STATE_HOME': str(self.root / 'state')}
        config, state = settings.config_path(environment), settings.state_path(environment)
        config.parent.mkdir(exist_ok=True)
        state.parent.mkdir(exist_ok=True)
        config.write_text('[Authenticators]\nFingerprint=true\n[Other]\nKeep=yes\n')
        state.write_text('[Greeter]\nAuthenticator=Fingerprint\n[Other]\nKeep=yes\n')
        return environment, config, state

    @unittest.skipUnless(shutil.which('kwriteconfig6') and shutil.which('kreadconfig6'), 'KDE tools required')
    def test_disable_resets_saved_fingerprint_and_backs_up_both_files(self):
        environment, config, state = self.apply_fixture()
        originals = {str(p): p.read_bytes() for p in (config, state)}
        calls = []
        real_run = subprocess.run
        def run(args, **kwargs):
            if args[0] == 'kwriteconfig6' and args[-1] == 'false':
                self.assertIn('Authenticator=Regular', state.read_text())
            calls.append(args)
            return real_run(args, **kwargs)
        with patch.dict(os.environ, environment), patch.object(settings.subprocess, 'run', side_effect=run):
            settings.apply(False, settings.snapshot(config)[2], settings.snapshot(state)[2])
        self.assertIn('Fingerprint=false', config.read_text())
        self.assertIn('Authenticator=Regular', state.read_text())
        for p in (config, state):
            self.assertIn('Keep=yes', p.read_text())
        records = list((state.parent / 'fingerprint-manager/kde-config-backups').glob('*.json'))
        self.assertEqual(len(records), 2)
        for record in records:
            payload = json.loads(record.read_text())
            self.assertEqual(base64.b64decode(payload['original']), originals[payload['path']])

    def test_failed_state_reset_never_disables_fingerprint(self):
        environment, config, state = self.apply_fixture()
        def fail(args, **kwargs):
            if args[0] == 'kreadconfig6':
                return SimpleNamespace(stdout='Fingerprint')
            raise subprocess.CalledProcessError(1, args)
        with patch.dict(os.environ, environment), patch.object(settings.subprocess, 'run', side_effect=fail) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                settings.apply(False, settings.snapshot(config)[2], settings.snapshot(state)[2])
        self.assertIn('Fingerprint=true', config.read_text())
        self.assertFalse(any(call.args[0][-1] == 'false' for call in run.call_args_list))

    def test_unverified_state_reset_never_disables_fingerprint(self):
        environment, config, state = self.apply_fixture()
        with patch.dict(os.environ, environment), patch.object(settings.subprocess, 'run', return_value=SimpleNamespace(stdout='Fingerprint')):
            with self.assertRaisesRegex(ValueError, 'left enabled'):
                settings.apply(False, settings.snapshot(config)[2], settings.snapshot(state)[2])
        self.assertIn('Fingerprint=true', config.read_text())

    def test_stale_state_aborts_before_writes_or_backups(self):
        environment, config, state = self.apply_fixture()
        digest = settings.snapshot(state)[2]
        state.write_text('[Greeter]\nAuthenticator=Regular\n')
        with patch.dict(os.environ, environment), patch.object(settings.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'changed'):
                settings.apply(False, settings.snapshot(config)[2], digest)
            run.assert_not_called()
        self.assertFalse((state.parent / 'fingerprint-manager').exists())

    @unittest.skipUnless(shutil.which('kwriteconfig6'), 'KDE tools required')
    def test_enable_preserves_remembered_method(self):
        environment, config, state = self.apply_fixture()
        original = state.read_bytes()
        with patch.dict(os.environ, environment):
            settings.apply(True, settings.snapshot(config)[2], '')
        self.assertEqual(state.read_bytes(), original)

    def test_relative_state_home_uses_standard_location(self):
        self.assertEqual(settings.state_path({'XDG_STATE_HOME': 'relative'}),
                         Path.home() / '.local/state/kscreenlockerrc')



if __name__ == '__main__':
    unittest.main()
