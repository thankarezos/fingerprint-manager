import argparse
import os
from pathlib import Path
import sys

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickWindow

from .backend import Backend, is_kde


def main():
    parser = argparse.ArgumentParser(description='Fingerprint Manager for fprintd')
    parser.add_argument('--demo', action='store_true', help='Use simulated data; never access fprintd or change PAM')
    parser.add_argument('--screenshot', type=Path, help='Save an interface screenshot and exit (requires --demo)')
    parser.add_argument('--page', choices=['fingerprints', 'authentication', 'kde', 'about'], default='fingerprints', help='Initial page')
    args = parser.parse_args()
    if args.screenshot and not args.demo:
        parser.error('--screenshot requires --demo')
    if is_kde():
        os.environ.setdefault('QT_QUICK_CONTROLS_STYLE', 'org.kde.desktop')
    app = QGuiApplication(sys.argv[:1])
    app.setApplicationName('Fingerprint Manager')
    app.setOrganizationName('FingerprintManager')
    app.setDesktopFileName('io.github.thankarezos.fingerprint-manager')
    app.setWindowIcon(QIcon.fromTheme('fingerprint'))
    engine = QQmlApplicationEngine()
    backend = Backend(demo=args.demo)
    engine.setInitialProperties({'backend': backend, 'currentPage': 'authentication' if args.page == 'kde' else args.page})
    engine.load(QUrl.fromLocalFile(str(Path(__file__).parent / 'qml' / 'Main.qml')))
    if not engine.rootObjects():
        return 1
    app.aboutToQuit.connect(backend.shutdown)
    if args.screenshot:
        def capture():
            window = engine.rootObjects()[0]
            ok = isinstance(window, QQuickWindow) and window.grabWindow().save(str(args.screenshot))
            app.exit(0 if ok else 1)
        QTimer.singleShot(1200, capture)
    elif not args.demo:
        QTimer.singleShot(0, backend.refresh)
    return app.exec()
