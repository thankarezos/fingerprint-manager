"""Plasma 6.8's user-level fingerprint authenticator opt-in."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import sys

ARGS = ['--file', 'kscreenlockerrc', '--group', 'Authenticators', '--key', 'Fingerprint']
COMMAND = 'kwriteconfig6 --file kscreenlockerrc --group Authenticators --key Fingerprint true'


def preview(enable):
    value = 'true' if enable else 'false'
    reset = ('' if enable else
             'If the remembered unlock method is Fingerprint, first switch it to Regular (password)\n'
             'in ' + str(state_path()) + ':\n'
             'kwriteconfig6 --file ' + str(state_path()) +
             ' --group Greeter --key Authenticator Regular\n\n')
    return ('Per-user KDE settings (no administrator privileges):\n\n' + reset +
            'kwriteconfig6 ' + ' '.join(ARGS) + ' ' + value +
            '\n\nThe original configuration and, when disabling, remembered unlock state are backed up first.')


def state_path(environment=None):
    environment = os.environ if environment is None else environment
    directory = Path(environment.get('XDG_STATE_HOME') or Path.home() / '.local/state')
    if not directory.is_absolute():
        directory = Path.home() / '.local/state'
    return directory / 'kscreenlockerrc'


def config_path(environment=None):
    environment = os.environ if environment is None else environment
    directory = Path(environment.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    if not directory.is_absolute():
        directory = Path.home() / '.config'
    return directory / 'kscreenlockerrc'


def snapshot(path):
    if path.is_symlink():
        raise ValueError('The screen-locker configuration is a symlink; review it manually.')
    present = path.exists()
    raw = path.read_bytes() if present else b''
    return present, raw, hashlib.sha256(bytes([present]) + raw).hexdigest()


def inspect(environment=None):
    environment = os.environ if environment is None else environment
    result = dict(available=False, enabled=False, detail='', digest='', preview='')
    if 'KDE' not in environment.get('XDG_CURRENT_DESKTOP', '').upper().split(':'):
        return result
    try:
        shell, reader, writer = [shutil.which(name) for name in ('plasmashell', 'kreadconfig6', 'kwriteconfig6')]
        if not all((shell, reader, writer)):
            raise ValueError('Plasma configuration tools are not available.')
        version = subprocess.run([shell, '--version'], capture_output=True, text=True, timeout=3, check=True)
        match = re.search(r'plasmashell\s+(\d+)\.(\d+)', version.stdout)
        if not match:
            raise ValueError('Could not determine the Plasma version.')
        if tuple(map(int, match.groups())) < (6, 8):
            result['detail'] = 'This explicit authenticator option is for Plasma 6.8 and later.'
            return result
        reading = subprocess.run([reader, *ARGS, '--default', 'false'], capture_output=True, text=True,
                                 timeout=3, check=True)
        value = reading.stdout.strip().lower()
        if value not in ('true', 'false', '1', '0', 'yes', 'no', 'on', 'off'):
            raise ValueError('Unrecognized fingerprint authenticator setting.')
        _, _, digest = snapshot(config_path(environment))
        state_digest = snapshot(state_path(environment))[2]
        active = value in ('true', '1', 'yes', 'on')
        result.update(available=True, enabled=active, digest=digest, state_digest=state_digest,
                      detail='Plasma 6.8+ fingerprint authenticator is ' + ('enabled.' if active else 'disabled.'),
                      preview=preview(not active))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result['detail'] = str(exc)
    return result


def backup(expected, path=None, directory=None):
    path = config_path() if path is None else Path(path)
    present, raw, digest = snapshot(path)
    if not expected or digest != expected:
        raise ValueError('KDE settings changed since the preview. Refresh and review them again.')
    if directory is None:
        state = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local/state')
        directory = state / 'fingerprint-manager' / 'kde-config-backups'
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, filename = tempfile.mkstemp(prefix='kscreenlockerrc-', suffix='.json', dir=directory)
    with os.fdopen(fd, 'w') as stream:
        json.dump(dict(path=str(path), present=present, original=base64.b64encode(raw).decode(), digest=digest), stream)
        stream.flush()
        os.fsync(stream.fileno())
    return filename


def apply(enable, expected, expected_state):
    """Run in a user process. Never disable a still-selected authenticator."""
    config, state = config_path(), state_path()
    # Check both previews before creating backups or writing either file.
    if snapshot(config)[2] != expected or (not enable and snapshot(state)[2] != expected_state):
        raise ValueError('KDE settings changed since the preview. Refresh and review them again.')
    backups = [backup(expected, config)]
    if not enable:
        backups.append(backup(expected_state, state))
        args = ['--file', str(state), '--group', 'Greeter', '--key', 'Authenticator']
        def selected():
            return subprocess.run(['kreadconfig6', *args, '--default', 'Regular'],
                                  capture_output=True, text=True, check=True, timeout=5).stdout.strip()
        if selected() == 'Fingerprint':
            subprocess.run(['kwriteconfig6', *args, 'Regular'], check=True, timeout=5)
            if selected() != 'Regular':
                raise ValueError('Could not select password unlocking. Fingerprint was left enabled.')
    # Absolute paths ensure the edited files match the previewed and backed-up files.
    args = ['--file', str(config), '--group', 'Authenticators', '--key', 'Fingerprint']
    subprocess.run(['kwriteconfig6', *args, 'true' if enable else 'false'], check=True, timeout=5)
    print('KDE configuration backups: ' + ', '.join(backups))


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4 or sys.argv[1] not in ('true', 'false'):
            raise ValueError('Expected target boolean and configuration/state preview digests.')
        apply(sys.argv[1] == 'true', sys.argv[2], sys.argv[3])
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
