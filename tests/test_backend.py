import sys
import time
import unittest
from unittest.mock import patch

from PySide6.QtCore import QCoreApplication, QProcess
from PySide6.QtTest import QTest

from fingerprint_manager.backend import Backend, is_kde, parse_fingers

APP = QCoreApplication.instance() or QCoreApplication([])


def wait_done(backend, timeout=5):
    deadline = time.monotonic() + timeout
    while backend.busy and time.monotonic() < deadline:
        APP.processEvents()
        QTest.qWait(10)
    if backend.busy:
        backend.shutdown()
        raise AssertionError('Operation did not finish')


class BackendTests(unittest.TestCase):
    def backend(self):
        backend = Backend(demo=True)
        self.addCleanup(backend.shutdown)
        return backend

    def test_desktop_detection(self):
        self.assertTrue(is_kde({'XDG_CURRENT_DESKTOP': 'KDE'}))
        self.assertTrue(is_kde({'XDG_CURRENT_DESKTOP': 'ubuntu:KDE'}))
        self.assertFalse(is_kde({'XDG_CURRENT_DESKTOP': 'GNOME'}))
        self.assertFalse(is_kde({'XDG_CURRENT_DESKTOP': 'notKDE'}))

    def test_parse_only_recognized_enrollments(self):
        self.assertEqual(parse_fingers(' - #0: right-index-finger\n - #1: right-thumb\n - #2: right-thumb'),
                         ['right-index-finger', 'right-thumb'])
        self.assertEqual(parse_fingers('No devices available\n#0: arbitrary-command'), [])

    def test_invalid_finger_does_not_start_process(self):
        backend = self.backend()
        backend.enroll('; rm -rf /')
        self.assertFalse(backend.busy)
        self.assertEqual(backend.tone, 'error')

    def test_demo_enrollment_and_deletion(self):
        backend = self.backend()
        backend.enroll('left-thumb')
        wait_done(backend)
        self.assertIn('left-thumb', backend.enrolled)
        backend.delete('left-thumb')
        self.assertNotIn('left-thumb', backend.enrolled)

    def test_cancelled_demo_cannot_mutate_later(self):
        backend = self.backend()
        backend.enroll('left-thumb')
        backend.cancel()
        backend.verify('right-thumb')
        wait_done(backend)
        self.assertNotIn('left-thumb', backend.enrolled)

    def test_adoption_notifies_the_completed_preview(self):
        backend = self.backend()
        observed = []
        backend.changed.connect(lambda: observed.append((backend.pamPreview, backend.pamCanApply)))
        backend.preparePam('sudo', 'adopt')
        self.assertIn('adopt this service', backend.pamPreview)
        self.assertEqual(observed[-1], (backend.pamPreview, True))

    def test_kde_preference_can_enable_and_disable(self):
        backend = self.backend()
        backend._kde = True
        for current, action, value in [(True, 'disable', 'false'), (False, 'enable', 'true')]:
            backend._kde_settings = dict(available=True, enabled=current, digest='demo', detail='fixture')
            with patch.object(backend, 'refreshPam'):
                backend.prepareKdeSetting()
            self.assertEqual(backend.pamAction, action)
            self.assertTrue(backend.pamCanApply)
            self.assertIn('Fingerprint ' + value, backend.pamPreview)
            self.assertFalse(backend.pamRequiresAdmin)
            with patch.object(backend, '_run') as run:
                backend.configurePam()
                run.assert_not_called()  # demo mode must not write real settings

    def test_failed_kde_readback_is_not_a_successful_disable(self):
        backend = self.backend()
        backend._operation = 'kde-setting'
        backend._review = {'target_enabled': False}
        backend._kde_settings = {'available': False, 'enabled': False}
        with patch.object(backend, 'refreshPam'), patch.object(backend, '_read'):
            backend._finished(0, QProcess.ExitStatus.NormalExit)
        self.assertEqual(backend.tone, 'error')

    def test_preview_confirmation_reuses_the_running_helper(self):
        import json
        from fingerprint_manager.pam_services import PREVIEW_PREFIX
        backend = self.backend()
        backend._review = {'service': 'sudo', 'action': 'restore'}
        payload = dict(service='sudo', digest='fixture-digest', preview='fixture diff')
        script = 'import json; print(' + repr(PREVIEW_PREFIX + json.dumps(payload)) + ', flush=True); answer=json.loads(input()); print("confirmed" if answer.get("confirm") else "cancelled", flush=True)'
        backend._run('pam-session', sys.executable, ['-u', '-c', script])
        deadline = time.monotonic() + 5
        while not backend.pamWaitingConfirmation and time.monotonic() < deadline:
            APP.processEvents()
            QTest.qWait(10)
        self.assertTrue(backend.pamWaitingConfirmation)
        self.assertTrue(backend.busy)
        self.assertEqual(backend.pamPreview, 'fixture diff')
        with patch.object(backend, '_run') as run:
            backend.configurePam()
            run.assert_not_called()
        wait_done(backend)
        self.assertIn('confirmed', backend.message)
        self.assertFalse(backend.pamWaitingConfirmation)

    def test_cancel_authorized_preview_sends_no_apply(self):
        import json
        from fingerprint_manager.pam_services import PREVIEW_PREFIX
        backend = self.backend()
        backend._review = {'service': 'sudo', 'action': 'restore'}
        payload = dict(service='sudo', digest='fixture', preview='diff')
        script = 'import json; print(' + repr(PREVIEW_PREFIX + json.dumps(payload)) + ', flush=True); answer=json.loads(input()); print("APPLIED" if answer.get("confirm") else "cancelled", flush=True)'
        backend._run('pam-session', sys.executable, ['-u', '-c', script])
        deadline = time.monotonic() + 5
        while not backend.pamWaitingConfirmation and time.monotonic() < deadline:
            APP.processEvents()
            QTest.qWait(10)
        self.assertTrue(backend.pamWaitingConfirmation)
        backend.cancelPamReview()
        wait_done(backend)
        self.assertNotIn('APPLIED', backend.log)
        self.assertIn('cancelled', backend.log)

    def test_real_process_match_and_no_match(self):
        # Execute only a fixture process: never contact fprintd or hardware.
        backend = self.backend()
        for output, tone in [('Verify result: verify-match (done)', 'positive'),
                             ('Verify result: verify-no-match (done)', 'warning')]:
            backend._run('verify', sys.executable, ['-u', '-c', f'print({output!r})'])
            wait_done(backend)
            self.assertEqual(backend.tone, tone)

    def test_process_error_is_reported(self):
        backend = self.backend()
        backend._run('verify', sys.executable, ['-u', '-c', 'print("Permission denied"); exit(1)'])
        wait_done(backend)
        self.assertEqual(backend.tone, 'error')
        self.assertIn('Permission denied', backend.message)

    def test_enrollment_requires_explicit_completion(self):
        backend = self.backend()
        backend._finger = 'left-thumb'
        backend._run('enroll', sys.executable, ['-u', '-c', 'print("enroll-stage-passed")'])
        wait_done(backend)
        self.assertEqual(backend.tone, 'error')
        self.assertNotIn('left-thumb', backend.enrolled)


if __name__ == '__main__':
    unittest.main()
