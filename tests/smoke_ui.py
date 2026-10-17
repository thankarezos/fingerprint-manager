"""Offscreen integration check. Uses demo data only; run in a separate process."""

import os
from pathlib import Path

from PySide6.QtCore import QMetaObject, QObject, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickItem, QQuickWindow
from PySide6.QtTest import QTest

from fingerprint_manager.backend import Backend, is_kde

app = QGuiApplication([])
engine = QQmlApplicationEngine()
warnings = []
engine.warnings.connect(lambda messages: warnings.extend(str(message) for message in messages))
backend = Backend(demo=True)
engine.setInitialProperties({'backend': backend})
engine.load(QUrl.fromLocalFile(str(Path(__file__).parents[1] / 'fingerprint_manager/qml/Main.qml')))
assert engine.rootObjects(), 'QML failed to load'
root = engine.rootObjects()[0]
assert isinstance(root, QQuickWindow)
QTest.qWait(200)

def find_visual(item, name):
    if item.objectName() == name:
        return item
    for child in item.childItems():
        found = find_visual(child, name)
        if found is not None:
            return found
    return None

tab = root.findChild(QObject, 'authenticationTab')
assert tab.property('visible'), 'Authentication controls must be available on every desktop'
assert [row['key'] for row in backend.authServices] == ['sudo', 'login', 'lock', 'polkit']
assert ('KDE' in backend.authServices[2]['title']) == is_kde()
root.setProperty('currentPage', 'authentication')
QTest.qWait(100)
for key in ('sudo', 'login', 'lock', 'polkit'):
    assert QMetaObject.invokeMethod(find_visual(root.contentItem(), 'review-' + key), 'clicked')
    pam_dialog = root.findChild(QObject, 'pamDialog')
    assert pam_dialog.property('visible'), 'Authentication changes must show a preview'
    assert '/etc/pam.d/' in backend.pamTarget
    assert not root.findChild(QObject, 'applyPamButton').property('enabled'), 'Demo must not authorize real changes'
    backend.configurePam()
    assert not backend.busy, 'Demo must not launch a privileged process'
    QMetaObject.invokeMethod(pam_dialog, 'reject')
owner = find_visual(root.contentItem(), 'owner-sudo')
assert 'Take over' in owner.property('text')
assert QMetaObject.invokeMethod(owner, 'clicked')
assert pam_dialog.property('visible')
assert backend.pamAction == 'adopt'
QTest.qWait(50)
assert root.findChild(QObject, 'pamPreviewText').property('text') == backend.pamPreview, 'QML shows a stale adoption preview'
assert backend.pamCanApply
QMetaObject.invokeMethod(pam_dialog, 'reject')
assert not backend.authServices[0]['managed'], 'Cancelled ownership preview changed state'
if is_kde():
    backend.prepareKdeSetting()
    assert pam_dialog.property('visible')
    assert not backend.pamRequiresAdmin
    assert 'kwriteconfig6' in backend.pamPreview
    backend.configurePam()
    assert not backend.busy
    QMetaObject.invokeMethod(pam_dialog, 'reject')
else:
    assert not backend.kdeConfigAvailable
# A private preview keeps the helper busy while still allowing confirmation.
from unittest.mock import patch
backend.demo = False
backend._operation = 'pam-session'
backend._busy = True
backend._pam_pending = True
backend._review = dict(service='sudo', action='restore', supported=True, enabled=False,
                       preview='fixture authorized diff', digest='fixture', title='sudo', target='/etc/pam.d/sudo')
with patch('fingerprint_manager.backend.helper_available', return_value=True), patch.object(backend.process, 'write') as write:
    backend.changed.emit()
    backend.pamReviewReady.emit()
    QTest.qWait(50)
    apply_button = root.findChild(QObject, 'applyPamButton')
    assert apply_button.property('enabled'), 'Authorized review cannot be confirmed while helper waits'
    QMetaObject.invokeMethod(apply_button, 'clicked')
    assert write.call_count == 1, 'Confirmation launched cancellation or duplicate writes'
    assert b'"confirm": true' in write.call_args.args[0]
backend.demo = True
backend._busy = False
backend._operation = ''
backend.changed.emit()
root.setProperty('currentPage', 'fingerprints')
root.setProperty('selectedFinger', 'left-thumb')
assert QMetaObject.invokeMethod(root.findChild(QObject, 'enrollButton'), 'clicked')
dialog = root.findChild(QObject, 'enrollDialog')
assert dialog.property('visible'), 'Enrollment must show a confirmation'
assert 'left-thumb' not in backend.enrolled
assert QMetaObject.invokeMethod(dialog, 'accept')
assert backend.busy
QTest.qWait(1400)
assert 'left-thumb' in backend.enrolled

assert QMetaObject.invokeMethod(root.findChild(QObject, 'deleteButton'), 'clicked')
dialog = root.findChild(QObject, 'deleteDialog')
assert dialog.property('visible'), 'Deletion must show a confirmation'
assert 'left-thumb' in backend.enrolled
assert QMetaObject.invokeMethod(dialog, 'reject')
assert 'left-thumb' in backend.enrolled, 'Dismissed deletion changed enrollment'
assert QMetaObject.invokeMethod(root.findChild(QObject, 'deleteButton'), 'clicked')
assert QMetaObject.invokeMethod(dialog, 'accept')
assert 'left-thumb' not in backend.enrolled

assert not warnings, '\n'.join(warnings)
root.close()
backend.shutdown()
print('QML smoke test passed:', os.environ.get('XDG_CURRENT_DESKTOP', 'unknown'))
