"""Conservative support for KDE's dedicated fingerprint PAM service.

No generic PAM editor: only uncomment a distribution-provided fingerprint rule.
The privileged CLI always uses the fixed system paths below.
"""

import argparse
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

TARGET = Path('/etc/pam.d/kde-fingerprint')
VENDOR = Path('/usr/lib/pam.d/kde-fingerprint')
STATE = Path('/var/lib/fingerprint-manager')
HELPER = Path('/usr/lib/fingerprint-manager/kde-pam-helper')
RULE = re.compile(r'^\s*-?auth\s+(required|requisite|sufficient)\s+(?:\S*/)?pam_fprintd\.so(?:\s|$)')


def enabled(text):
    return any(RULE.match(line) for line in text.splitlines())


def enable_text(text):
    if enabled(text):
        return text
    lines = text.splitlines(keepends=True)
    candidates = [i for i, line in enumerate(lines)
                  if line.lstrip().startswith('#') and RULE.match(line.lstrip()[1:])]
    if len(candidates) != 1:
        raise ValueError('No single disabled fingerprint rule was found. This PAM layout needs manual review.')
    i = candidates[0]
    lines[i] = lines[i].replace('#', '', 1)
    return ''.join(lines)


def read_regular(path, privileged=False):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f'Refusing non-regular file: {path}')
    if privileged and (info.st_uid != 0 or info.st_mode & 0o022):
        raise ValueError(f'Refusing file not exclusively controlled by root: {path}')
    return path.read_bytes()


def snapshot(target=TARGET, vendor=VENDOR, privileged=False):
    # lexists also detects dangling symlinks; never follow PAM symlinks.
    present = os.path.lexists(target)
    source = target if present else vendor
    raw = read_regular(source, privileged)
    text = raw.decode('utf-8')
    return present, source, raw, text


def inspect(target=TARGET, vendor=VENDOR, state=STATE):
    try:
        _, source, _, text = snapshot(target, vendor)
        proposed = enable_text(text)
        diff = ''.join(difflib.unified_diff(text.splitlines(True), proposed.splitlines(True),
                                         fromfile=str(source), tofile=str(target)))
        return dict(enabled=enabled(text), supported=True, source=str(source),
                    digest=hashlib.sha256(text.encode()).hexdigest(),
                    detail='Fingerprint authentication is configured.' if enabled(text)
                    else 'A disabled fingerprint rule can be enabled.',
                    preview=diff or 'Already configured. No PAM changes are needed.')
    except (OSError, UnicodeError, ValueError) as exc:
        return dict(enabled=False, supported=False, source='', detail=str(exc), preview='')


def atomic_write(path, content, mode):
    fd, name = tempfile.mkstemp(prefix='.fingerprint-manager-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def apply_enable(target=TARGET, vendor=VENDOR, state=STATE, privileged=True, expected=None):
    present, source, original, text = snapshot(target, vendor, privileged)
    if expected and hashlib.sha256(original).hexdigest() != expected:
        raise ValueError('PAM configuration changed since the preview. Refresh and review it again.')
    proposed = enable_text(text).encode()
    if proposed == original:
        return 'Already configured; no changes made.'
    state.mkdir(mode=0o700, exist_ok=True)
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or (privileged and (info.st_uid != 0 or info.st_mode & 0o077)):
        raise ValueError('Backup directory must be a private root-owned directory.')
    record = state / 'kde-fingerprint.json'
    if os.path.lexists(record):
        raise ValueError('A previous change is backed up. Restore it before applying another change.')
    mode = stat.S_IMODE(source.stat().st_mode)
    payload = dict(present=present, original=base64.b64encode(original).decode(),
                   applied=hashlib.sha256(proposed).hexdigest(), mode=mode)
    atomic_write(record, json.dumps(payload).encode(), 0o600)
    # Recheck immediately before mutation; configuration changed since preview is refused.
    if snapshot(target, vendor, privileged)[2] != original:
        record.unlink()
        raise ValueError('PAM configuration changed. Refresh and review it again.')
    atomic_write(target, proposed, mode)
    return 'KDE fingerprint rule enabled. The original configuration was backed up.'


def restore(target=TARGET, state=STATE, privileged=True):
    record = state / 'kde-fingerprint.json'
    payload = json.loads(read_regular(record, privileged))
    current = read_regular(target, privileged)
    if hashlib.sha256(current).hexdigest() != payload['applied']:
        raise ValueError('PAM configuration changed since this app edited it. Restore requires manual review.')
    if payload['present']:
        atomic_write(target, base64.b64decode(payload['original']), payload['mode'])
    else:
        target.unlink()
    record.unlink()
    return 'Original KDE fingerprint configuration restored.'


def main():
    parser = argparse.ArgumentParser(description='Manage only the dedicated kde-fingerprint PAM rule')
    parser.add_argument('action', choices=['enable', 'restore'])
    parser.add_argument('--expected', help='SHA-256 of the reviewed configuration')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'Administrator authorization is required.\n')
    try:
        print(apply_enable(expected=args.expected) if args.action == 'enable' else restore())
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f'{exc}\n')
