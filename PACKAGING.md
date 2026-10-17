# Distribution packaging

GUI source belongs in this repository. Maintain PKGBUILD / `.SRCINFO` separately
from driver packaging and from the AUR publishing checkout.

## Runtime dependencies

On Arch: `python`, `pyside6`, `kirigami`, `qqc2-desktop-style`, `fprintd` and
`polkit` (for the optional administrator helper). KDE users also need
`kconfig` for `kreadconfig6` / `kwriteconfig6` and Plasma 6.8+ for the explicit
fingerprint-authenticator preference. This per-user command runs without pkexec. A working libfprint driver is
provided through fprintd's dependencies. Do not require the CS9711-specific
driver; this GUI can manage any reader supported by the installed driver.
The `stdbuf` utility from coreutils provides immediate operation progress when
available. No service restart or PAM change belongs in package install hooks.

## Build and stage

Use Arch's Python build tooling without downloading dependencies with pip:

```sh
python -m build --wheel --no-isolation
python -m installer --destdir="$pkgdir" dist/*.whl
```

The wheel includes the Python package, QML, desktop entry and icon. Its entrypoint
is `fingerprint-manager`.

## Optional administrator helper

Distribution packaging can install the helper and policy into root-owned paths:

```sh
install -Dm755 data/kde-pam-helper \
  "$pkgdir/usr/lib/fingerprint-manager/kde-pam-helper"
install -Dm644 data/io.github.thankarezos.fingerprint-manager.policy \
  "$pkgdir/usr/share/polkit-1/actions/io.github.thankarezos.fingerprint-manager.policy"
```

These are staging commands for package creation, not commands to apply PAM changes.
The Python package must be installed in the system interpreter's site-packages,
not a user site or virtual environment. The helper uses Python isolated mode.
The app checks that the helper and its parent directories are root-owned and
not writable by group or others before invoking pkexec.

The executable retains its original `kde-pam-helper` filename for packaging
compatibility, but imports `fingerprint_manager.pam_services` and handles all
supported locations. Its PolicyKit action is
`io.github.thankarezos.fingerprint-manager.pam`.

The helper accepts enable/adopt/managed-toggle/restore operations and their
private-backup previews, plus an allowlisted service name. It accepts no filesystem path arguments. Privileged commands use
fixed PAM directories and backup locations. Shared include files are read-only; generated app-owned copies are managed separately.

Enable previews hash the full dependency graph, including override presence.
The helper rechecks this hash and recreates the plan before writing. Restore
previews require authorization to read private backups; the subsequent restore
requires a matching preview digest and refuses files edited after the app's
change. Operations are serialized with a private lock. Existing PAM files must
be root-owned regular files. Unknown layouts are refused rather than replaced.

The helper is deliberately not installed by pip. Until a system package installs
it, the GUI offers read-only authentication inspection and enable previews. Privileged PolicyKit
integration has not been exercised on a live authentication configuration.

Ownership is per service. Adoption stores the original without changing auth
behavior. Releasing ownership restores it. Direct fingerprint alternatives can
be disabled in place. Inherited alternatives use generated service-specific
include copies; the helper derives their names itself and accepts no arbitrary
include paths. New generations are written before the top-level service switches.
Edited app-owned copies block toggles and cleanup. Source-only execution still
requires the installed helper before any management operation can be applied.

Managed-operation previews use a single authorized helper process. The helper
fixes the service and action before presenting its preview and accepts one
bounded confirmation over stdin within two minutes. Cancellation, EOF, timeout,
a mismatched digest, or subsequently changed configuration prevents mutation.
The PolicyKit policy remains `auth_admin`; no authorization cache is introduced.
