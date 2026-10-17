"""Asynchronous fprintd command backend. Commands never run through a shell."""

import os
import json
import pwd
import re
import shutil
import signal
import stat
import sys

from PySide6.QtCore import QObject, Property, QProcess, QProcessEnvironment, QTimer, Signal, Slot

from . import pam_services, kde_settings

FINGERS = ['left-thumb', 'left-index-finger', 'left-middle-finger', 'left-ring-finger',
           'left-little-finger', 'right-thumb', 'right-index-finger', 'right-middle-finger',
           'right-ring-finger', 'right-little-finger']


def parse_fingers(output):
    return list(dict.fromkeys(re.findall(r'#\d+:\s*(' + '|'.join(FINGERS) + r')\b', output)))


def is_kde(environment=None):
    environment = os.environ if environment is None else environment
    return 'KDE' in environment.get('XDG_CURRENT_DESKTOP', '').upper().split(':')


def helper_available():
    try:
        for path in (pam_services.HELPER, *pam_services.HELPER.parents):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return False
        return os.access(pam_services.HELPER, os.X_OK) and bool(shutil.which('pkexec'))
    except OSError:
        return False


class Backend(QObject):
    changed = Signal()
    pamReviewReady = Signal()

    def __init__(self, demo=False):
        super().__init__()
        self.demo = demo
        self.username = pwd.getpwuid(os.getuid()).pw_name
        self._fingers = ['right-index-finger', 'right-thumb'] if demo else []
        self._busy = False
        self._message = 'Demo mode — no reader or system settings will be changed.' if demo else 'Ready to check your reader.'
        self._tone = 'information'
        self._device = 'Demo fingerprint reader' if demo else 'Reader not checked'
        self._output = ''
        self._operation = ''
        self._cancelled = False
        self._stages = 0
        self._finger = ''
        self._demo_generation = 0
        self._kde = is_kde()
        self._pam = {}
        self._auth_services = []
        self._login_choice = ""
        self._review = {}
        self._pam_pending = False
        self._pam_buffer = ""
        self._kde_settings = {}
        self._kde_backup = ""
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._read)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._error)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._timeout)
        self.refreshPam()

    busy = Property(bool, lambda self: self._busy, notify=changed)
    message = Property(str, lambda self: self._message, notify=changed)
    tone = Property(str, lambda self: self._tone, notify=changed)
    device = Property(str, lambda self: self._device, notify=changed)
    enrolled = Property('QStringList', lambda self: self._fingers, notify=changed)
    allFingers = Property('QStringList', lambda self: FINGERS, constant=True)
    userName = Property(str, lambda self: self.username, constant=True)
    demoMode = Property(bool, lambda self: self.demo, constant=True)
    kde = Property(bool, lambda self: self._kde, constant=True)
    log = Property(str, lambda self: self._output, notify=changed)
    authServices = Property('QVariantList', lambda self: self._auth_services, notify=changed)
    kdeConfigAvailable = Property(bool, lambda self: self._kde_settings.get('available', False), notify=changed)
    kdeConfigEnabled = Property(bool, lambda self: self._kde_settings.get('enabled', False), notify=changed)
    kdeConfigDetail = Property(str, lambda self: self._kde_settings.get('detail', ''), notify=changed)
    pamRequiresAdmin = Property(bool, lambda self: self._review.get('kind') != 'kde-setting', notify=changed)
    pamTitle = Property(str, lambda self: self._review.get('title', ''), notify=changed)
    pamPreview = Property(str, lambda self: self._review.get('preview', ''), notify=changed)
    pamDetail = Property(str, lambda self: self._review.get('detail', ''), notify=changed)
    pamTarget = Property(str, lambda self: self._review.get('target', ''), notify=changed)
    pamAction = Property(str, lambda self: self._review.get('action', 'enable'), notify=changed)
    pamCanApply = Property(bool, lambda self: bool(self._review.get('supported')) and not self._review.get('enabled', False), notify=changed)
    pamWaitingConfirmation = Property(bool, lambda self: self._pam_pending, notify=changed)
    helperReady = Property(bool, lambda self: not self.demo and helper_available(), notify=changed)

    def _say(self, message, tone='information'):
        self._message, self._tone = message, tone
        self.changed.emit()

    def _run(self, operation, program, arguments):
        if self._busy:
            return
        executable = shutil.which(program)
        if not executable:
            self._say(f'{program} is not installed. Install fprintd using your package manager.', 'error')
            return
        self._operation, self._output, self._cancelled = operation, '', False
        self._pam_pending, self._pam_buffer = False, ''
        self._busy = True
        env = QProcessEnvironment.systemEnvironment()
        env.insert('LC_ALL', 'C')
        self.process.setProcessEnvironment(env)
        self._say({'list': 'Checking your reader…', 'verify': 'Touch the selected finger to the reader.',
                   'enroll': 'Touch and lift your finger repeatedly.', 'delete': 'Removing the selected fingerprint…',
                   'pam': 'Waiting for administrator authorization…',
                   'pam-preview': 'Authorizing access to the saved configuration…',
                   'pam-session': 'Authorizing this configuration review…',
                   'kde-setting': 'Updating the fingerprint authenticator for your KDE account…'}[operation])
        # fprintd tools can otherwise buffer progress while stdout is a pipe.
        stdbuf = shutil.which('stdbuf') if operation not in ('pam', 'pam-preview', 'pam-session', 'kde-setting') else None
        self.process.start(stdbuf or executable, ['-oL', '-eL', executable, *arguments] if stdbuf else arguments)
        self.timer.start(180000 if operation in ('enroll', 'pam', 'pam-preview', 'pam-session') else 45000)

    @Slot()
    def refresh(self):
        self.refreshPam()
        if self.demo:
            self._say('Demo reader ready. Choose a finger to try the interface.')
            return
        self._run('list', 'fprintd-list', [self.username])

    def _valid(self, finger):
        if finger not in FINGERS:
            self._say('Choose a valid finger.', 'error')
            return False
        return not self._busy

    @Slot(str)
    def verify(self, finger):
        if not self._valid(finger):
            return
        if finger not in self._fingers:
            self._say('Enroll this finger before verifying it.', 'warning')
            return
        self._finger = finger
        if self.demo:
            self._simulate('Fingerprint matched. Demo verification complete.')
        else:
            self._run('verify', 'fprintd-verify', ['-f', finger, self.username])

    @Slot(str)
    def enroll(self, finger):
        if not self._valid(finger):
            return
        self._finger, self._stages = finger, 0
        if self.demo:
            self._simulate('Demo fingerprint enrolled.', lambda: self._fingers.append(finger)
                           if finger not in self._fingers else None)
        else:
            self._run('enroll', 'fprintd-enroll', ['-f', finger, self.username])

    @Slot(str)
    def delete(self, finger):
        if not self._valid(finger) or finger not in self._fingers:
            return
        if self.demo:
            self._fingers.remove(finger)
            self._say('Demo fingerprint removed.', 'positive')
        else:
            self._run('delete', 'fprintd-delete', [self.username, '-f', finger])

    def _simulate(self, message, action=None):
        self._demo_generation += 1
        generation = self._demo_generation
        self._busy = True
        self._cancelled = False
        self._say('Demo operation in progress…')
        def finish():
            if not self._cancelled and generation == self._demo_generation:
                if action:
                    action()
                self._busy = False
                self._say(message, 'positive')
        QTimer.singleShot(1200, finish)

    def _read(self):
        text = bytes(self.process.readAllStandardOutput()).decode('utf-8', errors='replace')
        self._output = (self._output + text)[-20000:]
        if self._operation == 'pam-session':
            self._pam_buffer += text
            while '\n' in self._pam_buffer:
                line, self._pam_buffer = self._pam_buffer.split('\n', 1)
                if line.startswith(pam_services.PREVIEW_PREFIX):
                    try:
                        result = json.loads(line[len(pam_services.PREVIEW_PREFIX):])
                        if result['service'] != self._review['service']:
                            raise ValueError('Unexpected preview service')
                        self._review.update(preview=result['preview'], digest=result['digest'], supported=True, enabled=False)
                        self._pam_pending = True
                        self._message = 'Review the change, then apply or cancel. Administrator authorization is already complete.'
                        self.changed.emit()
                        self.pamReviewReady.emit()
                    except (ValueError, KeyError, TypeError):
                        self.process.write(b'{"confirm": false}\n')
                        self._say('Could not read the authorized preview.', 'error')
            if len(self._pam_buffer) > 600000:
                self.process.write(b'{"confirm": false}\n')
                self._pam_buffer = ''
                self._say('The configuration preview is too large.', 'error')
        if self._operation == 'enroll':
            stages = self._output.count('enroll-stage-passed')
            if stages != self._stages:
                self._stages = stages
                self._message = f'{stages} sample(s) accepted. Lift and touch your finger again.'
        retry_messages = {'enroll-retry-scan': 'Try another touch.',
                          'enroll-swipe-too-short': 'Cover more of the reader.',
                          'enroll-finger-not-centered': 'Center your finger on the reader.',
                          'enroll-remove-and-retry': 'Lift your finger, then try again.',
                          'verify-retry-scan': 'Try another touch.',
                          'verify-no-match': 'No match. Try the same finger again.'}
        for token, message in retry_messages.items():
            if token in text:
                self._message = message
        self.changed.emit()

    def _finished(self, code, status):
        self.timer.stop()
        self._read()
        operation, output = self._operation, self._output
        self._busy = False
        if operation == 'pam-session':
            self._pam_pending = False
            self._review['supported'] = False
        if self._cancelled:
            self.changed.emit()
            return
        if code != 0 or status != QProcess.ExitStatus.NormalExit:
            if operation == 'list':
                self._fingers = []
                self._device = 'Reader unavailable'
            self._say(output.strip().splitlines()[-1] if output.strip() else 'Operation failed.', 'error')
            return
        if operation == 'list':
            self._fingers = parse_fingers(output)
            if 'No devices available' in output or 'found 0 devices' in output:
                self._device = 'No fingerprint reader found'
                self._say('No reader is available. Check the driver and USB connection.', 'warning')
            else:
                self._device = 'Fingerprint reader available'
                self._say(f'{len(self._fingers)} enrolled finger(s) for {self.username}.', 'positive')
        elif operation == 'verify':
            matched = 'verify-match' in output
            self._say('Fingerprint matched.' if matched else 'Fingerprint did not match.', 'positive' if matched else 'warning')
        elif operation == 'enroll':
            if 'enroll-completed' in output:
                if self._finger not in self._fingers:
                    self._fingers.append(self._finger)
                self._say('Fingerprint enrolled.', 'positive')
            else:
                self._say('Enrollment was not completed. Check the operation details.', 'error')
        elif operation == 'delete':
            # Re-query instead of assuming a particular fprintd delete output format.
            self.refresh()
        elif operation in ('pam', 'pam-session'):
            self.refreshPam()
            message = output.strip().splitlines()[-1] if output.strip() else 'Authentication configuration updated.'
            self._say(message, 'positive')
        elif operation == 'kde-setting':
            self.refreshPam()
            if self._kde_settings.get('available') and self._kde_settings.get('enabled') == self._review.get('target_enabled', True):
                state = 'enabled' if self._review.get('target_enabled', True) else 'disabled'
                self._say(f'KDE fingerprint authenticator {state} for your account. The PAM configuration is unchanged.', 'positive')
            else:
                self._say('KDE did not report the requested setting. Review the operation details and KDE configuration backups.', 'error')
        elif operation == 'pam-preview':
            try:
                result = json.loads(output)
                if result['service'] != self._review['service']:
                    raise ValueError('Unexpected restore service')
                self._review.update(preview=result['preview'], digest=result['digest'], supported=True, enabled=False)
                self.changed.emit()
                self.pamReviewReady.emit()
            except (ValueError, KeyError):
                self._say('Could not read the restore preview.', 'error')
        self.changed.emit()

    def _error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.timer.stop()
            self._busy = False
            self._say(self.process.errorString(), 'error')

    def _timeout(self):
        if self._operation in ('pam', 'pam-preview', 'pam-session'):
            self._say('The administrator operation is still running. Complete or dismiss its authorization dialog.', 'warning')
            return
        self.cancel()
        self._say('Operation timed out. You can try again.', 'warning')

    @Slot()
    def cancel(self):
        if self._busy and self._operation in ('pam', 'pam-preview', 'pam-session'):
            self._say('Cancel administrator authorization in its authentication dialog.', 'warning')
            return
        self._cancelled = True
        if self.demo:
            self._busy = False
        elif self.process.state() != QProcess.ProcessState.NotRunning:
            # fprintd handles SIGINT to release the device; force-stop only if stuck.
            try:
                os.kill(self.process.processId(), signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                pass
            QTimer.singleShot(2000, self._kill_cancelled)
        self._say('Operation cancelled.', 'warning')

    def _kill_cancelled(self):
        if self._cancelled and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()

    @Slot()
    def refreshPam(self):
        self._kde_settings = (dict(available=self._kde, enabled=False,
            detail='Demo: Plasma 6.8+ fingerprint authenticator is disabled.', digest='demo',
            preview='Demo — no user settings will change.\n\n' + kde_settings.COMMAND)
            if self.demo else kde_settings.inspect())
        if self.demo:
            self._auth_services = [dict(key=key, title=title, service=service, enabled=False,
                supported=True, managed=False, status='disabled', detail='Demo configuration; no system files are accessed.',
                preview='Demo preview: fingerprint authentication would be added for ' + service,
                digest='demo', sources=[], target='/etc/pam.d/' + service,
                choices=['sddm', 'plasmalogin'] if key == 'login' else [])
                for key, title, service in [('sudo', 'sudo', 'sudo'), ('login', 'Login screen', 'sddm'),
                    ('lock', 'Lock screen (KDE)' if self._kde else 'Lock screen',
                     'kde-fingerprint' if self._kde else 'gdm-fingerprint'),
                    ('polkit', 'Administrator prompts (Polkit)', 'polkit-1')]]
        else:
            store = pam_services.PamStore()
            self._auth_services = pam_services.locations(store)
            if self._login_choice:
                row = next(row for row in self._auth_services if row['key'] == 'login')
                if self._login_choice in row['choices']:
                    selected = store.inspect(self._login_choice)
                    selected.update(key='login', title='Login screen', choices=row['choices'])
                    self._auth_services[self._auth_services.index(row)] = selected
        self.changed.emit()

    @Slot(str)
    def selectLoginService(self, service):
        row = next((row for row in self._auth_services if row['key'] == 'login'), {})
        if not self._busy and service in row.get('choices', []):
            self._login_choice = service
            self.refreshPam()
            if self.demo:
                self._auth_services[1].update(service=service, target='/etc/pam.d/' + service,
                    preview='Demo preview for ' + service)
                self.changed.emit()

    @Slot()
    def prepareKdeSetting(self):
        if self._busy or not self._kde:
            return
        self.refreshPam()
        settings = self._kde_settings
        if not settings.get('available'):
            self._say(settings.get('detail') or 'This KDE option is not available.', 'warning')
            return
        desired = not settings['enabled']
        self._review = dict(kind='kde-setting', action='enable' if desired else 'disable',
            title='KDE fingerprint authenticator', target=str(kde_settings.config_path()),
            supported=True, enabled=False, target_enabled=desired,
            preview=kde_settings.preview(desired), digest=settings['digest'], state_digest=settings.get('state_digest', ''), detail=settings['detail'])
        self.changed.emit()
        self.pamReviewReady.emit()

    @Slot(str, str)
    def preparePam(self, key, action):
        if self._busy or action not in ('enable', 'restore', 'adopt', 'disable', 'enable-managed'):
            return
        self.refreshPam()
        row = next((row for row in self._auth_services if row['key'] == key), None)
        if not row or row['service'] not in pam_services.ALLOWED:
            self._say('Choose a supported authentication service.', 'error')
            return
        self._review = dict(row, action=action)
        if action == 'enable' and not row.get('managed'):
            self._review.update(supported=False, preview='External configuration is read-only. Select Fingerprint Manager as the owner to enable managed controls.\n\n' + row.get('preview', ''))
        self.changed.emit()
        if action == 'adopt':
            if self.demo:
                self._review.update(preview='Demo: adopt this service without changing authentication behavior.', supported=True, enabled=False)
            else:
                try:
                    plan = pam_services.PamStore().adopt_plan(row['service'])
                    self._review.update(preview=plan['preview'], digest=plan['digest'], supported=True, enabled=False)
                except (OSError, ValueError) as exc:
                    self._say(str(exc), 'error')
                    return
        if action in ('restore', 'disable', 'enable-managed'):
            if self.demo:
                self._review.update(preview='Demo managed-operation preview. No files will change.', supported=True, enabled=False)
            elif helper_available():
                self._run('pam-session', 'pkexec', [str(pam_services.HELPER), 'review-' + action, row['service']])
                return
            else:
                self._say('Install the packaged administrator helper to review a private backup.', 'error')
                return
        # Publish the completed preview, including adoption/managed-operation
        # updates, before QML opens the dialog.
        self.changed.emit()
        self.pamReviewReady.emit()

    @Slot()
    def cancelPamReview(self):
        if self._pam_pending:
            self._pam_pending = False
            self._review['supported'] = False
            self._cancelled = True
            self.process.write(b'{"confirm": false}\n')
            self.changed.emit()

    @Slot()
    def configurePam(self):
        if self._pam_pending:
            answer = dict(confirm=True, expected=self._review.get('digest'))
            self._pam_pending = False
            self._review['supported'] = False
            self.process.write((json.dumps(answer) + '\n').encode())
            self._say('Applying the confirmed configuration change…')
            return
        if self._busy or not self._review.get('supported') or self._review.get('enabled'):
            return
        if self.demo:
            self._say('Demo mode does not apply authentication changes.')
            return
        if self._review.get('kind') == 'kde-setting':
            value = 'true' if self._review.get('target_enabled', True) else 'false'
            self._run('kde-setting', sys.executable, ['-m', 'fingerprint_manager.kde_settings', value,
                      self._review.get('digest', ''), self._review.get('state_digest', '')])
            return
        if not helper_available():
            self._say('The administrator helper must be installed by your package manager first.', 'error')
            return
        service = self._review.get('service')
        action = self._review.get('action')
        digest = self._review.get('digest')
        if service not in pam_services.ALLOWED or action not in ('enable', 'restore', 'adopt', 'disable', 'enable-managed') or not digest:
            self._say('Refresh and review the configuration before applying it.', 'error')
            return
        self._run('pam', 'pkexec', [str(pam_services.HELPER), action, service, '--expected', digest])

    def shutdown(self):
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(1500):
                self.process.kill()
                self.process.waitForFinished(1000)
