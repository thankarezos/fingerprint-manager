"""PAM discovery and narrowly scoped, reviewed authentication-location changes.

Only allowlisted service files can be written. Includes are inspected, never
edited. No claim is made to simulate every PAM control-flow possibility.
"""

import argparse
import base64
import difflib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import select
import sys
import time
from contextlib import contextmanager

from .kde_pam import atomic_write, enable_text, read_regular

HELPER = Path('/usr/lib/fingerprint-manager/kde-pam-helper')
ALLOWED = {'sudo', 'polkit-1', 'sddm', 'plasmalogin', 'lightdm', 'gdm-fingerprint',
           'kde-fingerprint', 'xfce4-screensaver', 'light-locker',
           'mate-screensaver', 'cinnamon-screensaver'}
NATIVE = {'kde-fingerprint', 'gdm-fingerprint'}
LOGIN = {'sddm', 'plasmalogin', 'lightdm', 'gdm-fingerprint'}
MARKER = '# Fingerprint Manager: managed fingerprint authentication'
ENTRY = re.compile(r'^\s*(-?\w+)\s+(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*))?$')
NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')


class PamStore:
    def __init__(self, etc=Path('/etc/pam.d'), vendor=Path('/usr/lib/pam.d'),
                 state=Path('/var/lib/fingerprint-manager'),
                 os_release=Path('/etc/os-release'),
                 display_manager=Path('/etc/systemd/system/display-manager.service'),
                 privileged=False):
        self.etc, self.vendor, self.state = Path(etc), Path(vendor), Path(state)
        self.os_release, self.display_manager = Path(os_release), Path(display_manager)
        self.privileged = privileged

    def source(self, service):
        if not NAME.fullmatch(service):
            raise ValueError('Invalid PAM include name.')
        target = self.etc / service
        return target if os.path.lexists(target) else self.vendor / service

    def graph(self, service):
        records, rules, errors = {}, [], []
        visits = 0
        def visit(name, chain):
            nonlocal visits
            visits += 1
            if name in chain:
                raise ValueError('PAM include cycle: ' + ' → '.join((*chain, name)))
            if len(chain) >= 32 or len(records) >= 128 or visits > 256:
                raise ValueError('PAM include graph is too large to review automatically.')
            path = self.source(name)
            raw = read_regular(path, self.privileged)
            if len(raw) > 65536:
                raise ValueError('PAM service file exceeds the supported size.')
            text = raw.decode('utf-8')
            records[name] = (path, raw)
            if '\\\n' in text:
                raise ValueError('PAM line continuations require manual review.')
            for index, line in enumerate(text.splitlines()):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                if stripped.startswith('@include '):
                    if len(stripped.split()) != 2:
                        raise ValueError('Malformed PAM @include rule.')
                    visit(stripped.split()[1], (*chain, name))
                    continue
                match = ENTRY.match(line)
                if not match:
                    if stripped.startswith(('auth', '-auth', '@')):
                        raise ValueError(f'Unrecognized PAM rule in {name}:{index + 1}')
                    continue
                kind, control, module, args = match.groups()
                if kind.lstrip('-') != 'auth':
                    continue
                if control in ('include', 'substack'):
                    visit(module, (*chain, name))
                else:
                    rules.append(dict(service=name, index=index, kind=kind,
                                      control=control, module=Path(module).name,
                                      module_path=module, args=args or '', line=line))
        try:
            visit(service, ())
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(str(exc))
        digest_data = [(name, str(path), raw.hex()) for name, (path, raw) in sorted(records.items())]
        digest_data.append(('override-present', os.path.lexists(self.etc / service)))
        digest = hashlib.sha256(json.dumps(digest_data).encode()).hexdigest()
        return records, rules, errors, digest

    def arch_family(self):
        try:
            values = dict(line.split('=', 1) for line in self.os_release.read_text().splitlines()
                          if '=' in line and not line.startswith('#'))
            family = (values.get('ID', '') + ' ' + values.get('ID_LIKE', '')).replace('"', '').replace("'", '').split()
            return 'arch' in family
        except OSError:
            return False

    def proposed(self, service, records, rules):
        path, raw = records[service]
        text = raw.decode()
        if service in NATIVE:
            proposed = enable_text(text)
            if proposed == text:
                return text
            # A newly enabled sufficient rule could skip later mandatory checks.
            # Dedicated fingerprint services need a required/requisite rule.
            for line in proposed.splitlines():
                match = ENTRY.match(line)
                if match and Path(match.group(3)).name == 'pam_fprintd.so':
                    if match.group(2) not in ('required', 'requisite'):
                        raise ValueError('This native fingerprint rule could bypass later checks; manual review is required.')
            return MARKER + '\n' + proposed
        if not self.arch_family():
            raise ValueError('Automatic rule insertion is supported on Arch-family systems only. This distribution needs a reviewed profile.')
        # Refuse unknown authentication modules / MFA stacks rather than bypassing them.
        credentials = {'pam_unix.so', 'pam_systemd_home.so'}
        gates = {'pam_shells.so', 'pam_nologin.so', 'pam_env.so'}
        optional = {'pam_permit.so', 'pam_gnome_keyring.so', 'pam_kwallet5.so'}
        preconditions = []
        has_password = False
        for rule in rules:
            module, control, args = rule['module'], rule['control'], rule['args']
            if module in credentials:
                has_password = True
            elif module in gates and control in ('required', 'requisite'):
                preconditions.append(rule['line'].strip())
            elif module == 'pam_faillock.so':
                words = args.split()
                if 'preauth' in words and control in ('required', 'requisite'):
                    preconditions.append(rule['line'].strip())
                elif 'authfail' not in words and 'authsucc' not in words:
                    raise ValueError('Unrecognized pam_faillock rule; manual review is required.')
            elif module not in optional or control != 'optional':
                raise ValueError(f'Authentication rule {module} requires manual review; no fingerprint shortcut will be inserted.')
        if not has_password:
            raise ValueError('No recognized password fallback was found.')
        # Put the whole new block before all existing auth rules, leaving all
        # original numeric jumps and their targets at the same relative offsets.
        # Repeat inherited mandatory gates before the fingerprint shortcut.
        lines = text.splitlines(keepends=True)
        position = next((i for i, line in enumerate(lines)
                         if line.lstrip().startswith(('auth ', 'auth\t', '-auth ', '-auth\t', '@include '))), None)
        if position is None:
            raise ValueError('No authentication insertion point was found.')
        block = [MARKER, '# Preserve mandatory checks from the effective authentication stack.',
                 *dict.fromkeys(preconditions), 'auth sufficient pam_fprintd.so', '# End Fingerprint Manager block']
        lines.insert(position, '\n'.join(block) + '\n')
        return ''.join(lines)

    def inspect(self, service):
        result = dict(service=service, enabled=False, supported=False, managed=False,
                      origin='local' if os.path.lexists(self.etc / service) else 'vendor',
                      status='unknown', detail='', preview='', digest='', sources=[], target=str(self.etc / service))
        if service not in ALLOWED:
            result['detail'] = 'Choose a supported PAM service.'
            return result
        records, rules, errors, digest = self.graph(service)
        result.update(digest=digest, sources=[str(path) for path, _ in records.values()])
        fingerprints = [rule for rule in rules if rule['module'] == 'pam_fprintd.so']
        if service in records:
            text = records[service][1].decode()
            result['managed'] = MARKER in text.splitlines()
        result['adoptable'] = not errors and not result['managed']
        if errors:
            result['detail'] = 'Configuration needs review: ' + '; '.join(errors)
            return result
        if fingerprints:
            result.update(enabled=True, status='managed' if result['managed'] else 'external',
                          detail='Fingerprint rule found in ' + ', '.join(dict.fromkeys(rule['service'] for rule in fingerprints)) +
                          '. Runtime authentication has not been tested.',
                          preview='Already configured. Existing rules are left unchanged.')
            return result
        if result['managed']:
            result.update(status='managed', supported=True, detail='App-managed configuration has no active fingerprint rule. Use the managed controls to enable it.')
            return result
        try:
            proposed = self.proposed(service, records, rules)
            original = records[service][1].decode()
            result.update(status='managed' if result['managed'] else 'disabled', supported=True,
                          detail='A fingerprint rule can be enabled after review and administrator authorization.',
                          preview=''.join(difflib.unified_diff(original.splitlines(True), proposed.splitlines(True),
                                                             fromfile=str(records[service][0]), tofile=str(self.etc / service))))
        except ValueError as exc:
            result['detail'] = str(exc)
        return result

    @contextmanager
    def locked(self):
        self.state.mkdir(mode=0o700, exist_ok=True)
        info = self.state.lstat()
        if not stat.S_ISDIR(info.st_mode) or (self.privileged and (info.st_uid != 0 or info.st_mode & 0o077)):
            raise ValueError('Backup directory must be a private root-owned directory.')
        fd = os.open(self.state / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def enable(self, service, expected):
        if service not in ALLOWED:
            raise ValueError('Unsupported authentication service.')
        with self.locked():
            plan = self.inspect(service)
            if not expected or plan['digest'] != expected:
                raise ValueError('PAM configuration changed since the preview. Refresh and review it again.')
            if plan['enabled']:
                return 'Already configured; no changes made.'
            if not plan['supported']:
                raise ValueError(plan['detail'])
            records, rules, errors, digest = self.graph(service)
            if errors or digest != expected:
                raise ValueError('PAM configuration changed during review.')
            source, raw = records[service]
            proposed = self.proposed(service, records, rules).encode()
            target = self.etc / service
            record = self.state / f'{service}.json'
            if os.path.lexists(record):
                raise ValueError('A backup already exists. Restore it before making another change.')
            mode = stat.S_IMODE(source.stat().st_mode)
            payload = dict(present=os.path.lexists(target), original=base64.b64encode(raw).decode(),
                           applied=hashlib.sha256(proposed).hexdigest(), mode=mode)
            atomic_write(record, json.dumps(payload).encode(), 0o600)
            if self.graph(service)[3] != expected:
                record.unlink()
                raise ValueError('PAM configuration changed before applying the preview.')
            atomic_write(target, proposed, mode)
        return f'Fingerprint authentication configured for {service}. Original configuration backed up.'

    def verify_artifacts(self, payload):
        for name, data in payload.get('artifacts', {}).items():
            if not NAME.fullmatch(name) or not name.startswith('fingerprint-manager-'):
                raise ValueError('Invalid managed include name.')
            current = read_regular(self.etc / name, self.privileged)
            if hashlib.sha256(current).hexdigest() != data['applied']:
                raise ValueError('An app-owned PAM include was edited externally; manual review is required.')

    def adopt_plan(self, service):
        plan = self.inspect(service)
        if not plan.get('adoptable'):
            raise ValueError('This service cannot be adopted automatically. Review its configuration first.')
        records, _, errors, _ = self.graph(service)
        if errors:
            raise ValueError('; '.join(errors))
        raw = records[service][1]
        proposed = MARKER.encode() + b'\n' + raw
        return dict(service=service, digest=plan['digest'], proposed=proposed,
            preview='Take ownership without changing authentication behavior. Save the original for returning to external management.\n\n' +
            ''.join(difflib.unified_diff(raw.decode().splitlines(True), proposed.decode().splitlines(True),
                                       fromfile=str(records[service][0]), tofile=str(self.etc / service))))

    def adopt(self, service, expected):
        if service not in ALLOWED:
            raise ValueError('Unsupported authentication service.')
        with self.locked():
            plan = self.adopt_plan(service)
            if not expected or plan['digest'] != expected:
                raise ValueError('Configuration changed since the adoption preview.')
            record = self.state / f'{service}.json'
            if os.path.lexists(record):
                raise ValueError('An earlier backup exists; restore it before adopting again.')
            source = self.source(service)
            raw = read_regular(source, self.privileged)
            payload = dict(present=os.path.lexists(self.etc / service), original=base64.b64encode(raw).decode(),
                applied=hashlib.sha256(plan['proposed']).hexdigest(), mode=stat.S_IMODE(source.stat().st_mode))
            atomic_write(record, json.dumps(payload).encode(), 0o600)
            if self.graph(service)[3] != expected:
                record.unlink()
                raise ValueError('Configuration changed before adoption.')
            atomic_write(self.etc / service, plan['proposed'], payload['mode'])
        return f'{service} is now managed by this app. Authentication behavior was preserved.'

    def managed_plan(self, service, action, payload=None):
        if service not in ALLOWED or action not in ('disable', 'enable-managed'):
            raise ValueError('Unsupported managed operation.')
        if payload is None:
            payload = json.loads(read_regular(self.state / f'{service}.json', self.privileged))
        current = read_regular(self.etc / service, self.privileged)
        if hashlib.sha256(current).hexdigest() != payload['applied']:
            raise ValueError('This service was edited externally. Review it before changing it.')
        self.verify_artifacts(payload)
        records, rules, errors, digest = self.graph(service)
        if errors:
            raise ValueError('; '.join(errors))
        old_artifacts = dict(payload.get('artifacts', {}))
        if action == 'enable-managed':
            if 'enabled_root' not in payload:
                if any(rule['module'] == 'pam_fprintd.so' for rule in rules):
                    raise ValueError('Fingerprint authentication is already configured.')
                proposed_text = self.proposed(service, records, rules)
                # Adoption already added the marker; keep only one copy.
                parts = proposed_text.split(MARKER + '\n')
                proposed = (parts[0] + MARKER + '\n' + ''.join(parts[1:])).encode()
                payload['enabled_root'] = base64.b64encode(proposed).decode()
                return dict(service=service, digest=digest, proposed=proposed, changes={}, payload=payload,
                            old_artifacts={}, preview=''.join(difflib.unified_diff(current.decode().splitlines(True),
                                proposed.decode().splitlines(True), fromfile=str(self.etc / service),
                                tofile=str(self.etc / service))))
            templates = {service: base64.b64decode(payload['enabled_root'])}
            templates.update({name: base64.b64decode(data['enabled']) for name, data in old_artifacts.items()})
        else:
            fingerprint_rules = [rule for rule in rules if rule['module'] == 'pam_fprintd.so']
            if not fingerprint_rules:
                raise ValueError('No active fingerprint rule was found.')
            if service not in NATIVE and not any(rule['module'] in ('pam_unix.so', 'pam_systemd_home.so') for rule in rules):
                raise ValueError('No known password fallback exists; disabling requires manual review.')
            for rule in fingerprint_rules:
                if rule['control'] != 'sufficient' and not (service in NATIVE and rule['control'] in ('required', 'requisite')):
                    raise ValueError('This fingerprint control is not safe to disable automatically.')
            inherited = any(rule['service'] != service for rule in fingerprint_rules)
            templates = {service: current}
            if inherited or old_artifacts:
                templates.update({name: raw for name, (_, raw) in records.items() if name != service})
        generation = hashlib.sha256((digest + action).encode()).hexdigest()[:10]
        names = {name: f'fingerprint-manager-{service}-{generation}-{hashlib.sha256(name.encode()).hexdigest()[:8]}'
                 for name in templates if name != service}
        for name in names.values():
            if len(name) > 200 or os.path.lexists(self.etc / name):
                raise ValueError('A managed include name is already in use or too long.')
        # Commenting removes a PAM entry; retain slots whenever a numeric jump
        # could jump across a removed rule in the effective graph. Required native factors must still fail
        # while disabled, rather than accidentally allowing an empty auth stack.
        last_fingerprint = max((i for i, rule in enumerate(rules) if rule['module'] == 'pam_fprintd.so'), default=-1)
        has_numeric_jumps = any(re.search(r'=\s*\d+(?=\s|\])', rule['control'])
                                for rule in rules[:last_fingerprint])
        def rewrite(raw, disable):
            lines = raw.decode().splitlines(keepends=True)
            for index, line in enumerate(lines):
                match = ENTRY.match(line)
                if match and match.group(1).lstrip('-') == 'auth':
                    kind, control, module, _ = match.groups()
                    if control in ('include', 'substack') and module in names:
                        lines[index] = line[:match.start(3)] + names[module] + line[match.end(3):]
                    elif disable and Path(module).name == 'pam_fprintd.so':
                        if control == 'sufficient' and not has_numeric_jumps:
                            lines[index] = '# Fingerprint Manager: disabled: ' + line
                        else:
                            lines[index] = f'{kind} {control} pam_deny.so # Fingerprint Manager: fingerprint disabled\n'
                elif line.strip().startswith('@include '):
                    old = line.strip().split()[1]
                    if old in names:
                        lines[index] = line.replace(old, names[old], 1)
            return ''.join(lines).encode()
        enabled_root = rewrite(templates[service], False)
        proposed = rewrite(templates[service], action == 'disable')
        changes, artifacts = {}, {}
        for old, new in names.items():
            enabled = rewrite(templates[old], False)
            raw = rewrite(templates[old], action == 'disable')
            changes[new] = raw
            artifacts[new] = dict(enabled=base64.b64encode(enabled).decode(), applied=hashlib.sha256(raw).hexdigest(),
                                  mode=old_artifacts[old].get('mode', 0o644) if old in old_artifacts else stat.S_IMODE(records[old][0].stat().st_mode))
        payload.update(enabled_root=base64.b64encode(enabled_root).decode(), artifacts=artifacts)
        preview = ''.join(difflib.unified_diff(current.decode().splitlines(True), proposed.decode().splitlines(True),
                          fromfile=str(self.etc / service), tofile=str(self.etc / service)))
        for name, raw in changes.items():
            preview += '\n' + ''.join(difflib.unified_diff([], raw.decode().splitlines(True),
                                         fromfile='/dev/null', tofile=str(self.etc / name)))
        for name in old_artifacts:
            preview += f'\nRemove unchanged app-owned include: {self.etc / name}\n'
        if changes:
            preview = 'Service-specific include snapshots isolate this change; shared originals are not edited. Review these snapshots after distribution PAM updates.\n\n' + preview
        return dict(service=service, digest=digest, preview=preview, proposed=proposed,
                    changes=changes, payload=payload, old_artifacts=old_artifacts)

    def local_plan(self, service, action):
        """Edit the effective local configuration, without an ownership step."""
        if service not in ALLOWED or action not in ('local-enable', 'local-disable', 'create-override'):
            raise ValueError('Unsupported local configuration operation.')
        records, rules, errors, digest = self.graph(service)
        if errors:
            raise ValueError('; '.join(errors))
        local = os.path.lexists(self.etc / service)
        if (action == 'create-override') == local:
            raise ValueError('Vendor files are read-only. Create a local override first; local files can be edited directly.')
        source, current = records[service]
        record = self.state / f'{service}.json'
        previous = json.loads(read_regular(record, self.privileged)) if os.path.lexists(record) else None
        matches = previous and hashlib.sha256(current).hexdigest() == previous['applied']
        if previous and not matches and previous.get('artifacts'):
            raise ValueError('The local configuration and its generated includes diverged. Review the changes manually.')
        payload = previous if matches else dict(present=local,
            original=base64.b64encode(current).decode(), applied=hashlib.sha256(current).hexdigest(),
            mode=stat.S_IMODE(source.stat().st_mode))
        enabled = any(rule['module'] == 'pam_fprintd.so' for rule in rules)
        if action == 'local-disable' or (action == 'local-enable' and matches and 'enabled_root' in payload):
            return self.managed_plan(service, 'disable' if action == 'local-disable' else 'enable-managed', payload)
        if action == 'local-enable' and enabled:
            raise ValueError('Fingerprint authentication is already enabled.')
        proposed = current if enabled else self.proposed(service, records, rules).encode()
        preview = ''.join(difflib.unified_diff(current.decode().splitlines(True), proposed.decode().splitlines(True),
                         fromfile=str(source), tofile=str(self.etc / service)))
        if not local:
            preview = 'Create a local override. The vendor file remains unchanged.\n\n' + (preview or current.decode())
        return dict(service=service, digest=digest, preview=preview, proposed=proposed,
                    changes={}, old_artifacts={}, payload=payload)

    def set_local(self, service, action, expected):
        return self.set_managed(service, action, expected, local=True)

    def set_managed(self, service, action, expected, local=False):
        with self.locked():
            plan = self.local_plan(service, action) if local else self.managed_plan(service, action)
            if not expected or plan['digest'] != expected:
                raise ValueError('Configuration changed since the managed preview.')
            payload = plan['payload']
            record = self.state / f'{service}.json'
            original_record = read_regular(record, self.privileged) if os.path.lexists(record) else None
            target_present = os.path.lexists(self.etc / service)
            current_root = read_regular(self.source(service), self.privileged)
            if local:
                history = self.state / 'history'
                history.mkdir(mode=0o700, exist_ok=True)
                # Keep a snapshot of each edit, even when a later local edit establishes a new baseline.
                atomic_write(history / f'{service}-{time.time_ns()}.json', json.dumps(dict(
                    present=target_present, original=base64.b64encode(current_root).decode(),
                    previous_record=base64.b64encode(original_record).decode() if original_record else None)).encode(), 0o600)
            created = []
            try:
                for name, raw in plan['changes'].items():
                    atomic_write(self.etc / name, raw, payload['artifacts'][name]['mode'])
                    created.append(name)
                if self.graph(service)[3] != expected:
                    raise ValueError('Configuration changed before applying the managed preview.')
                # New include generations are staged first. Switch the complete
                # service last, preserving jump offsets and substack boundaries.
                payload['applied'] = hashlib.sha256(plan['proposed']).hexdigest()
                atomic_write(record, json.dumps(payload).encode(), 0o600)
                atomic_write(self.etc / service, plan['proposed'], payload['mode'])
            except (OSError, ValueError):
                # Ordinary write failures leave the original service and record usable.
                root_now = read_regular(self.source(service), self.privileged)
                if root_now == plan['proposed']:
                    if target_present:
                        atomic_write(self.etc / service, current_root, payload['mode'])
                    elif os.path.lexists(self.etc / service):
                        (self.etc / service).unlink()
                elif root_now != current_root:
                    raise ValueError('Configuration changed during recovery; manual review is required.')
                if original_record is not None:
                    atomic_write(record, original_record, 0o600)
                elif os.path.lexists(record):
                    record.unlink()
                for name in created:
                    (self.etc / name).unlink()
                raise
            for name in plan['old_artifacts']:
                (self.etc / name).unlink()
        return f'Local fingerprint configuration updated for {service}. Backup saved.'

    def restore_plan(self, service):
        if service not in ALLOWED:
            raise ValueError('Unsupported authentication service.')
        payload = json.loads(read_regular(self.state / f'{service}.json', self.privileged))
        target = self.etc / service
        self.verify_artifacts(payload)
        current = read_regular(target, self.privileged)
        if hashlib.sha256(current).hexdigest() != payload['applied']:
            raise ValueError('Configuration was edited after this app changed it. Restore requires manual review.')
        original = base64.b64decode(payload['original'])
        vendor_digest = ''
        if payload['present']:
            preview = ''.join(difflib.unified_diff(current.decode().splitlines(True), original.decode().splitlines(True),
                                                 fromfile=str(target), tofile=str(target) + ' (restored)'))
        else:
            # Show the vendor configuration that will become effective again.
            vendor = read_regular(self.vendor / service, self.privileged)
            vendor_digest = hashlib.sha256(vendor).hexdigest()
            preview = 'Remove the app-created override; the current vendor file becomes effective.\n\n'
            preview += ''.join(difflib.unified_diff(current.decode().splitlines(True), vendor.decode().splitlines(True),
                                                  fromfile=str(target), tofile=str(self.vendor / service)))
        digest = hashlib.sha256((self.graph(service)[3] + vendor_digest).encode()).hexdigest()
        for name in payload.get('artifacts', {}):
            raw = read_regular(self.etc / name, self.privileged)
            preview += '\n' + ''.join(difflib.unified_diff(raw.decode().splitlines(True), [],
                                      fromfile=str(self.etc / name), tofile='/dev/null'))
        return dict(service=service, preview=preview, digest=digest, payload=payload)

    def restore(self, service, expected):
        with self.locked():
            plan = self.restore_plan(service)
            if not expected or plan['digest'] != expected:
                raise ValueError('PAM configuration changed since the restore preview.')
            payload, target = plan['payload'], self.etc / service
            if payload['present']:
                atomic_write(target, base64.b64decode(payload['original']), payload['mode'])
            else:
                target.unlink()
            for name in payload.get('artifacts', {}):
                (self.etc / name).unlink()
            (self.state / f'{service}.json').unlink()
        return f'Original configuration restored for {service}.'


def locations(store=None, environment=None):
    store = store or PamStore()
    environment = os.environ if environment is None else environment
    desktop = set(environment.get('XDG_CURRENT_DESKTOP', '').upper().split(':'))
    available = sorted(name for name in LOGIN if os.path.lexists(store.source(name)))
    try:
        unit = store.display_manager.resolve(strict=True).name
    except (OSError, RuntimeError):
        unit = ''
    login_service = {'sddm.service': 'sddm', 'plasmalogin.service': 'plasmalogin',
                     'plasma-login-manager.service': 'plasmalogin', 'lightdm.service': 'lightdm',
                     'gdm.service': 'gdm-fingerprint'}.get(unit, '')
    lock = 'kde-fingerprint' if 'KDE' in desktop else 'gdm-fingerprint' if 'GNOME' in desktop else ''
    if 'XFCE' in desktop:
        lock = next((name for name in ('xfce4-screensaver', 'light-locker') if os.path.lexists(store.source(name))), '')
    elif 'MATE' in desktop:
        lock = 'mate-screensaver'
    elif desktop.intersection({'CINNAMON', 'X-CINNAMON'}):
        lock = 'cinnamon-screensaver'
    result = []
    for key, title, service in [('sudo', 'sudo', 'sudo'), ('login', 'Login screen', login_service),
                                ('lock', 'Lock screen (KDE)' if 'KDE' in desktop else 'Lock screen', lock),
                                ('polkit', 'Administrator prompts (Polkit)', 'polkit-1')]:
        plan = store.inspect(service)
        plan.update(key=key, title=title, choices=available if key == 'login' else [])
        if not service:
            plan['detail'] = 'Select your login manager.' if key == 'login' else 'No supported screen locker was detected for this desktop.'
        result.append(plan)
    return result


PREVIEW_PREFIX = 'FINGERPRINT_MANAGER_PREVIEW='


def confirmation(stream, timeout):
    deadline = time.monotonic() + timeout
    data = b''
    while len(data) <= 1024:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream.fileno()], [], [], remaining)[0]:
            raise ValueError('The configuration review expired. Open a fresh preview.')
        chunk = os.read(stream.fileno(), min(1025 - len(data), 1024))
        if not chunk:
            return None
        data += chunk
        if b'\n' in data:
            if len(data) > 1024:
                break
            return json.loads(data.split(b'\n', 1)[0])
    raise ValueError('Invalid confirmation message.')


def interactive_review(store, service, action, input_stream=None, output_stream=None, timeout=120):
    """One authorized helper, one fixed action, one preview and confirmation."""
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    with store.locked():
        plan = (store.restore_plan(service) if action == 'restore' else
                store.local_plan(service, action) if action in ('local-enable', 'local-disable', 'create-override') else
                store.managed_plan(service, action))
    public = {key: plan[key] for key in ('service', 'preview', 'digest')}
    encoded = PREVIEW_PREFIX + json.dumps(public)
    if len(encoded.encode()) > 512000:
        raise ValueError('This preview is too large; manual review is required.')
    print(encoded, file=output_stream, flush=True)
    answer = confirmation(input_stream, timeout)
    if answer is not None and not isinstance(answer, dict):
        raise ValueError('Invalid confirmation message.')
    if not answer or answer.get('confirm') is not True:
        return 'Configuration review cancelled; no changes made.'
    if answer.get('expected') != plan['digest']:
        raise ValueError('The confirmation does not match the authorized preview.')
    if action == 'restore':
        return store.restore(service, plan['digest'])
    if action in ('local-enable', 'local-disable', 'create-override'):
        return store.set_local(service, action, plan['digest'])
    return store.set_managed(service, action, plan['digest'])


def main():
    parser = argparse.ArgumentParser(description='Configure allowlisted fingerprint authentication services')
    parser.add_argument('action', choices=['review-local-enable', 'review-local-disable', 'review-create-override', 'enable', 'preview-restore', 'restore', 'adopt', 'disable', 'enable-managed', 'preview-disable', 'preview-enable-managed', 'review-restore', 'review-disable', 'review-enable-managed'])
    parser.add_argument('service', choices=sorted(ALLOWED))
    parser.add_argument('--expected')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'Administrator authorization is required.\n')
    store = PamStore(privileged=True)
    try:
        if args.action.startswith('review-'):
            print(interactive_review(store, args.service, args.action.removeprefix('review-')))
        elif args.action == 'enable':
            print(store.enable(args.service, args.expected))
        elif args.action == 'adopt':
            print(store.adopt(args.service, args.expected))
        elif args.action in ('disable', 'enable-managed'):
            print(store.set_managed(args.service, args.action, args.expected))
        elif args.action in ('preview-disable', 'preview-enable-managed'):
            with store.locked():
                plan = store.managed_plan(args.service, args.action.removeprefix('preview-'))
                print(json.dumps({key: plan[key] for key in ('service', 'preview', 'digest')}))
        elif args.action == 'restore':
            print(store.restore(args.service, args.expected))
        else:
            with store.locked():
                result = store.restore_plan(args.service)
                result.pop('payload')
                print(json.dumps(result))
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f'{exc}\n')
