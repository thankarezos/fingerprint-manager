# Fingerprint Manager

A Qt 6 / Kirigami desktop application for managing fingerprints through
`fprintd`. It works with readers supported by your installed libfprint driver;
it is not specific to Chipsailing hardware.

**This project is heavily vibecoded (developed with substantial AI assistance).**
It is experimental, and bugs are expected. Review authentication changes carefully
and keep a working password login available.

## Features

- View enrolled fingers for your current account.
- Enroll, verify, and remove an individual fingerprint.
- See enrollment progress and operation errors without blocking the interface.
- Configure fingerprint authentication separately for sudo, the login screen, and the lock screen.
- Detect existing rules in service files and inherited PAM includes.
- Preview supported changes, authorize them, and restore the saved originals.
- Try the interface in demo mode without accessing a reader or system settings.

Driver installation and updates stay with your distribution's package manager.
The application uses the default device selected by the fprintd command-line
tools. It does not yet offer a chooser for multiple connected readers.

## Run from source

On Arch Linux / EndeavourOS, install runtime dependencies:

```sh
sudo pacman -S --needed pyside6 kirigami qqc2-desktop-style fprintd
```

From this repository:

```sh
python3 -m fingerprint_manager --demo
```

To use your reader and existing enrollment:

```sh
python3 -m fingerprint_manager
```

The application runs as your regular user. fprintd handles authorization for
fingerprint operations. Enrollment replacement and deletion require confirmation.
Cancelling a new enrollment is not guaranteed to restore a previous template;
fprintd owns enrollment storage and replacement behavior.

Qt/Kirigami also runs on GNOME and other desktops, where the Authentication
page selects the corresponding locker instead of KDE’s service. Install the corresponding PySide6, Kirigami, and fprintd packages
for your distribution. Actual GNOME desktop integration has not yet been tested.

## Authentication locations

The Authentication page provides separate controls for:

- **sudo** — the `sudo` PAM service.
- **Login screen** — the detected active SDDM, Plasma Login Manager, LightDM, or
  GDM fingerprint service. If detection is unavailable, select an installed
  supported service explicitly.
- **Lock screen** — the current desktop's service. KDE uses `kde-fingerprint`;
  GNOME uses `gdm-fingerprint`. Known Xfce, MATE and Cinnamon lockers are also
  recognized. An unknown locker is shown for manual review.

- **Administrator prompts (Polkit)** — the `polkit-1` PAM service used for
  graphical privilege-authorization prompts, including KDE's authentication popup.

KDE fingerprint unlock is the lock-screen control, rather than a second toggle
editing another KDE authentication stack.

### Plasma 6.8 user preference

Plasma 6.8 also requires the fingerprint authenticator to be enabled for your
account, independently of the PAM rule. The KDE lock-screen card shows both
states and provides separate enable/disable actions for the Plasma fingerprint option.
Enabling uses:

```sh
kwriteconfig6 --file kscreenlockerrc --group Authenticators --key Fingerprint true
```

This command runs as your regular user after a preview. It never uses sudo or
the administrator helper. The application backs up the original user file in
`$XDG_STATE_HOME/fingerprint-manager/kde-config-backups` (normally
`~/.local/state/fingerprint-manager/kde-config-backups`) and refuses stale
previews. Before disabling with `false`, the application checks the remembered unlock method
in `$XDG_STATE_HOME/kscreenlockerrc` (normally `~/.local/state/kscreenlockerrc`).
If it is `Fingerprint`, it switches it to `Regular` (password) and verifies the
change before disabling the option. This avoids leaving Plasma 6.8 with a selected
authenticator that is no longer available. Both files are backed up before disabling;
a stale state file or failed reset aborts the operation. Each action previews the requested
value before applying it. Other user settings are kept
by KConfig's writer. Enabling this preference does not enable a missing PAM rule;
review both statuses in the lock-screen card.

### PAM configuration

Detection prefers `/etc/pam.d/<service>` over the vendor file in `/usr/lib/pam.d`
and follows authentication `include`, `substack`, and `@include` references.
Missing files, include cycles and unsupported syntax are reported as unknown,
not as proof fingerprint authentication is disabled. The app reports rule
presence; it does not simulate every possible PAM control-flow outcome.

Each service provides an ownership action:

- **Take over configuration** previews taking ownership and saves the original before
  enabling managed controls. Taking ownership itself does not alter authentication.
- **Restore external configuration** previews restoring the saved original
  and removes the app's ownership. It restores the original enabled/disabled state,
  rather than silently keeping the app's latest settings.

Managed services offer **Enable fingerprint** and **Disable fingerprint**. A
later external edit blocks automatic changes and restoration until reviewed.
Disabling a required fingerprint factor in a mixed authentication stack or a
service with no recognized password fallback is refused for manual review.

For inherited fingerprint alternatives, the application creates service-specific
copies of the include graph. It keeps include/substack boundaries and numeric
jump positions intact, replacing supported fingerprint alternatives with a failing
module while disabled. Only the chosen service references these copies; other
services and the shared originals remain unchanged. Each toggle stages a new
include generation before switching the service. Returning to external restores
the original file and deletes only unchanged app-owned copies. These snapshots
shadow updates to their original auth includes and need review after distribution
PAM updates. Direct service rules do not require include copies.

For dedicated KDE/GDM fingerprint services, the helper can uncomment a single
existing disabled rule. For newly enabled allowlisted services, automatic insertion is
limited to recognized Arch-family authentication layouts. The preview puts a
fingerprint alternative before the existing authentication sequence, preserving
its numeric jumps, and repeats recognized mandatory shell, login, environment,
and account-lock checks before that alternative. Unknown modules, including
unrecognized multi-factor stacks, are refused for manual review.

Only the chosen service and its app-owned include copies can change. Shared
original files such as `system-auth` and `system-login` are read but never edited. If a vendor service is used, the change
creates a complete `/etc/pam.d` override; that override shadows subsequent vendor
updates and should be reviewed after distribution changes.

Applying a change requires an exact preview and administrator authorization.
The helper rejects changes when the service or any included input changed since
review. Originals are saved privately in `/var/lib/fingerprint-manager`.
Restoration and managed toggles authorize one helper session, display the exact
diff, then wait for confirmation within that same session. Closing the preview
cancels it, and an unanswered review expires after two minutes. No second
authentication prompt is required for the confirmed operation. Later edits
by another tool or administrator cause restoration to be refused.

Applying changes requires the root-owned helper and PolicyKit policy to be
installed by distribution packaging. Running from source supports detection and
previews; it does not install the helper automatically. See
[PACKAGING.md](PACKAGING.md). The app never locks the screen or restarts services.

Test `fprintd-verify` before manually testing login, sudo or screen unlock.
Keep a working password available. Fingerprint login does not supply a password
for unlocking your keyring or wallet. Configuration detection alone cannot prove
compatibility with Plasma 6.8 or other desktop versions; live authentication
integration has not been tested by the automated suite.

## Development checks

```sh
python3 -m unittest discover -s tests -v
qmllint fingerprint_manager/qml/Main.qml
QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software \
  QT_QUICK_CONTROLS_STYLE=Basic PYTHONPATH=. python3 tests/smoke_ui.py
python3 -m build --wheel --no-isolation
```

The tests use simulated operations, fixture processes, and temporary PAM files.
They never enroll or delete real fingerprints or write system PAM files.

To capture a demo screenshot:

```sh
QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software \
  python3 -m fingerprint_manager --demo --screenshot /tmp/fingerprint-manager.png
```

Use `--page authentication` or `--page about` to select an initial page.
`--page kde` remains an alias for Authentication. The lock-screen service follows
the detected desktop; KDE-specific service selection is not used on GNOME.

## Credits and license

Inspired by [Mahmud Farooque's CS9711 Manager](https://github.com/mmhfarooque/chipsailing-cs9711-fingerprint-linux).
This is a new Qt implementation; the original GTK application and its installer
scripts are not bundled. See [NOTICE](NOTICE) and [LICENSE](LICENSE).
