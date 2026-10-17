import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami

Kirigami.ApplicationWindow {
    id: window
    required property QtObject backend
    width: 920
    height: 760
    minimumWidth: 600
    minimumHeight: 620
    title: qsTr("Fingerprint Manager")
    property string currentPage: "fingerprints"
    property string selectedFinger: "right-index-finger"
    property bool selectedEnrolled: backend.enrolled.indexOf(selectedFinger) >= 0
    function fingerLabel(name: string): string {
        const names = {
            "left-thumb": qsTr("Left thumb"), "left-index-finger": qsTr("Left index finger"),
            "left-middle-finger": qsTr("Left middle finger"), "left-ring-finger": qsTr("Left ring finger"),
            "left-little-finger": qsTr("Left little finger"), "right-thumb": qsTr("Right thumb"),
            "right-index-finger": qsTr("Right index finger"), "right-middle-finger": qsTr("Right middle finger"),
            "right-ring-finger": qsTr("Right ring finger"), "right-little-finger": qsTr("Right little finger")
        }
        return names[name] || name;
    }

    pageStack.initialPage: Kirigami.ScrollablePage {
        title: window.currentPage === "fingerprints" ? qsTr("Your fingerprints")
             : window.currentPage === "authentication" ? qsTr("Authentication locations") : qsTr("About")
        actions: [
            Kirigami.Action {
                text: qsTr("Refresh")
                icon.name: "view-refresh"
                enabled: !backend.busy
                onTriggered: backend.refresh()
            }
        ]

        ColumnLayout {
            spacing: Kirigami.Units.largeSpacing * 2

            RowLayout {
                spacing: Kirigami.Units.largeSpacing
                Kirigami.Icon {
                    source: "fingerprint"
                    implicitWidth: 48
                    implicitHeight: 48
                }
                ColumnLayout {
                    spacing: 2
                    Kirigami.Heading { text: qsTr("Fingerprint Manager"); level: 1 }
                    Controls.Label {
                        text: qsTr("Manage your reader and fingerprint enrollment.")
                        color: Kirigami.Theme.disabledTextColor
                    }
                }
                Item { Layout.fillWidth: true }
                Controls.Label {
                    visible: backend.demoMode
                    text: qsTr("DEMO")
                    font.bold: true
                    color: Kirigami.Theme.linkColor
                }
            }

            RowLayout {
                Controls.Button {
                    text: qsTr("Fingerprints")
                    icon.name: "fingerprint"
                    checkable: true
                    checked: window.currentPage === "fingerprints"
                    onClicked: window.currentPage = "fingerprints"
                }
                Controls.Button {
                    objectName: "authenticationTab"
                    text: qsTr("Authentication")
                    icon.name: "system-lock-screen"
                    checkable: true
                    checked: window.currentPage === "authentication"
                    onClicked: { backend.refreshPam(); window.currentPage = "authentication"; }
                }
                Item { Layout.fillWidth: true }
                Controls.ToolButton {
                    text: qsTr("About")
                    icon.name: "help-about"
                    onClicked: window.currentPage = "about"
                }
            }

            Kirigami.InlineMessage {
                Layout.fillWidth: true
                visible: backend.message.length > 0
                text: backend.message
                type: backend.tone === "error" ? Kirigami.MessageType.Error
                    : backend.tone === "positive" ? Kirigami.MessageType.Positive
                    : backend.tone === "warning" ? Kirigami.MessageType.Warning
                    : Kirigami.MessageType.Information
            }

            ColumnLayout {
                visible: window.currentPage === "fingerprints"
                Layout.fillWidth: true
                spacing: Kirigami.Units.largeSpacing * 2

                Kirigami.AbstractCard {
                    Layout.fillWidth: true
                    contentItem: RowLayout {
                        spacing: Kirigami.Units.largeSpacing
                        Kirigami.Icon { source: "input-touchpad"; implicitWidth: 32; implicitHeight: 32 }
                        ColumnLayout {
                            Layout.fillWidth: true
                            Controls.Label { text: backend.device; font.bold: true; Layout.fillWidth: true; wrapMode: Text.Wrap }
                            Controls.Label {
                                text: qsTr("Account: %1 · %2 enrolled").arg(backend.userName).arg(backend.enrolled.length)
                                color: Kirigami.Theme.disabledTextColor
                            }
                        }
                        Controls.BusyIndicator { visible: backend.busy; running: backend.busy; implicitWidth: 32; implicitHeight: 32 }
                    }
                }

                ColumnLayout {
                    spacing: Kirigami.Units.smallSpacing
                    Kirigami.Heading { text: qsTr("Choose a finger"); level: 2 }
                    Controls.Label {
                        text: qsTr("Select a finger to enroll, verify, or remove.")
                        color: Kirigami.Theme.disabledTextColor
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.largeSpacing
                    Repeater {
                        model: [qsTr("Left hand"), qsTr("Right hand")]
                        delegate: ColumnLayout {
                            id: hand
                            required property int index
                            required property string modelData
                            Layout.fillWidth: true
                            Layout.preferredWidth: 1
                            spacing: Kirigami.Units.smallSpacing
                            Controls.Label { text: hand.modelData; font.bold: true }
                            Repeater {
                                model: backend.allFingers.slice(hand.index * 5, hand.index * 5 + 5)
                                delegate: Controls.Button {
                                    required property string modelData
                                    Layout.fillWidth: true
                                    text: window.fingerLabel(modelData)
                                    icon.name: backend.enrolled.indexOf(modelData) >= 0 ? "emblem-ok-symbolic" : "list-add"
                                    checkable: true
                                    checked: window.selectedFinger === modelData
                                    enabled: !backend.busy
                                    Accessible.description: backend.enrolled.indexOf(modelData) >= 0 ? qsTr("Enrolled") : qsTr("Not enrolled")
                                    onClicked: window.selectedFinger = modelData
                                }
                            }
                        }
                    }
                }

                Kirigami.AbstractCard {
                    Layout.fillWidth: true
                    contentItem: ColumnLayout {
                        spacing: Kirigami.Units.largeSpacing
                        Controls.Label { text: window.fingerLabel(window.selectedFinger); font.bold: true }
                        Controls.Label {
                            text: window.selectedEnrolled ? qsTr("Enrolled and ready to verify") : qsTr("No fingerprint saved for this finger")
                            color: Kirigami.Theme.disabledTextColor
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                        }
                        RowLayout {
                            Controls.Button {
                                objectName: "enrollButton"
                                text: window.selectedEnrolled ? qsTr("Enroll again…") : qsTr("Enroll…")
                                icon.name: "list-add"
                                enabled: !backend.busy
                                onClicked: enrollDialog.open()
                            }
                            Controls.Button {
                                objectName: "verifyButton"
                                text: qsTr("Verify")
                                icon.name: "emblem-ok-symbolic"
                                enabled: !backend.busy && window.selectedEnrolled
                                onClicked: backend.verify(window.selectedFinger)
                            }
                            Item { Layout.fillWidth: true }
                            Controls.ToolButton {
                                objectName: "deleteButton"
                                text: qsTr("Remove…")
                                icon.name: "edit-delete"
                                enabled: !backend.busy && window.selectedEnrolled
                                onClicked: deleteDialog.open()
                            }
                        }
                    }
                }
                Controls.Button {
                    visible: backend.busy
                    text: qsTr("Cancel operation")
                    icon.name: "process-stop"
                    onClicked: backend.cancel()
                }
            }

            ColumnLayout {
                visible: window.currentPage === "authentication"
                Layout.fillWidth: true
                spacing: Kirigami.Units.largeSpacing
                Controls.Label {
                    text: qsTr("Choose external or app-managed configuration separately for each location. Taking ownership saves the original first. Returning to external restores that original configuration.")
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                }
                Repeater {
                    model: backend.authServices
                    delegate: Kirigami.AbstractCard {
                        id: locationCard
                        required property var modelData
                        objectName: "authLocation-" + modelData.key
                        Layout.fillWidth: true
                        contentItem: ColumnLayout {
                            spacing: Kirigami.Units.largeSpacing
                            RowLayout {
                                Kirigami.Icon {
                                    source: locationCard.modelData.key === "sudo" ? "utilities-terminal"
                                          : locationCard.modelData.key === "login" ? "system-users"
                                          : locationCard.modelData.key === "polkit" ? "dialog-password" : "system-lock-screen"
                                    implicitWidth: 28
                                    implicitHeight: 28
                                }
                                Kirigami.Heading { text: locationCard.modelData.title; level: 2; Layout.fillWidth: true }
                                Controls.Label {
                                    text: locationCard.modelData.status === "external" ? qsTr("PAM configured externally")
                                         : locationCard.modelData.status === "managed" ? qsTr("Managed by this app")
                                         : locationCard.modelData.status === "disabled" ? qsTr("Not configured") : qsTr("Needs review")
                                    font.bold: true
                                }
                            }
                            RowLayout {
                                Controls.Button {
                                    objectName: "owner-" + locationCard.modelData.key
                                    text: locationCard.modelData.managed ? qsTr("Restore external configuration…") : qsTr("Take over configuration…")
                                    icon.name: locationCard.modelData.managed ? "edit-undo" : "document-edit"
                                    enabled: !backend.busy && locationCard.modelData.service.length > 0
                                        && (!locationCard.modelData.managed || backend.helperReady || backend.demoMode)
                                    onClicked: backend.preparePam(locationCard.modelData.key, locationCard.modelData.managed ? "restore" : "adopt")
                                }
                                Controls.Label {
                                    visible: locationCard.modelData.managed
                                    text: locationCard.modelData.enabled ? qsTr("Fingerprint enabled") : qsTr("Fingerprint disabled")
                                    font.bold: true
                                }
                            }
                            Controls.Label {
                                text: locationCard.modelData.service ? qsTr("PAM service: %1").arg(locationCard.modelData.service)
                                                                    : qsTr("No service selected")
                                color: Kirigami.Theme.disabledTextColor
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                            }
                            Controls.ComboBox {
                                visible: locationCard.modelData.key === "login" && locationCard.modelData.choices.length > 0
                                enabled: !backend.busy
                                model: locationCard.modelData.choices
                                currentIndex: locationCard.modelData.choices.indexOf(locationCard.modelData.service)
                                displayText: currentIndex < 0 ? qsTr("Select login manager…") : currentText
                                Accessible.name: qsTr("Login manager PAM service")
                                onActivated: backend.selectLoginService(currentText)
                            }
                            Controls.Label {
                                text: locationCard.modelData.detail
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                            }
                            Controls.Label {
                                visible: locationCard.modelData.sources.length > 0
                                text: qsTr("Read from: %1").arg(locationCard.modelData.sources.join(", "))
                                color: Kirigami.Theme.disabledTextColor
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                            }
                            Controls.Label {
                                visible: locationCard.modelData.service === "kde-fingerprint" && backend.kde
                                text: backend.kdeConfigDetail
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                font.bold: true
                            }
                            Controls.Button {
                                objectName: "kdePreferenceButton"
                                visible: locationCard.modelData.service === "kde-fingerprint" && backend.kdeConfigAvailable
                                text: backend.kdeConfigEnabled ? qsTr("Disable Plasma fingerprint option…") : qsTr("Enable Plasma fingerprint option…")
                                icon.name: "preferences-system"
                                enabled: !backend.busy
                                onClicked: backend.prepareKdeSetting()
                            }
                            RowLayout {
                                Controls.Button {
                                    objectName: "review-" + locationCard.modelData.key
                                    text: locationCard.modelData.managed
                                        ? (locationCard.modelData.enabled ? qsTr("Disable fingerprint…") : qsTr("Enable fingerprint…"))
                                        : qsTr("Review existing configuration")
                                    icon.name: "document-preview"
                                    enabled: !backend.busy && (locationCard.modelData.managed || locationCard.modelData.supported || locationCard.modelData.enabled)
                                    onClicked: backend.preparePam(locationCard.modelData.key, locationCard.modelData.managed
                                        ? (locationCard.modelData.enabled ? "disable" : "enable-managed") : "enable")
                                }
                            }
                        }
                    }
                }
                Kirigami.InlineMessage {
                    Layout.fillWidth: true
                    visible: !backend.helperReady
                    text: qsTr("Running from source supports detection and previews. Applying changes requires the packaged administrator helper.")
                    type: Kirigami.MessageType.Information
                }
                Controls.Label {
                    text: qsTr("A detected rule does not prove authentication will succeed. Test verification first. Fingerprint login may leave your keyring or wallet locked until you enter its password.")
                    color: Kirigami.Theme.disabledTextColor
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                }
            }

            ColumnLayout {
                visible: window.currentPage === "about"
                Layout.fillWidth: true
                spacing: Kirigami.Units.largeSpacing
                Kirigami.Heading { text: qsTr("One manager. Any supported reader."); level: 2 }
                Controls.Label {
                    text: qsTr("Fingerprint Manager 0.1.0\n\nA Qt 6 / Kirigami frontend for fprintd. Your installed libfprint driver provides hardware support. Driver installation and updates stay with your package manager.\n\nInspired by Mahmud Farooque’s CS9711 Manager. This interface and backend are a new implementation.\n\nMIT License")
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                }
                Controls.Button {
                    text: qsTr("Project on GitHub")
                    icon.name: "globe"
                    onClicked: Qt.openUrlExternally("https://github.com/thankarezos/fingerprint-manager")
                }
            }

            Controls.Button {
                text: details.visible ? qsTr("Hide operation details") : qsTr("Show operation details")
                flat: true
                onClicked: details.visible = !details.visible
            }
            Controls.ScrollView {
                id: details
                visible: false
                Layout.fillWidth: true
                Layout.preferredHeight: 150
                Controls.TextArea {
                    text: backend.log || qsTr("No operation output yet.")
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.Wrap
                    font.family: "monospace"
                }
            }
        }
    }

    Controls.Dialog {
        id: enrollDialog
        objectName: "enrollDialog"
        anchors.centerIn: parent
        width: Math.min(window.width - 48, 480)
        title: window.selectedEnrolled ? qsTr("Replace this fingerprint?") : qsTr("Enroll fingerprint")
        modal: true
        standardButtons: Controls.Dialog.Ok | Controls.Dialog.Cancel
        onAccepted: backend.enroll(window.selectedFinger)
        contentItem: Controls.Label {
            text: window.selectedEnrolled
                ? qsTr("Enroll %1 again? The existing enrollment for this finger will be replaced.").arg(window.fingerLabel(window.selectedFinger))
                : qsTr("Enroll %1 for %2. Touch and lift your finger as prompted. Authorization may be requested by fprintd.").arg(window.fingerLabel(window.selectedFinger)).arg(backend.userName)
            wrapMode: Text.Wrap
        }
    }
    Controls.Dialog {
        id: deleteDialog
        objectName: "deleteDialog"
        anchors.centerIn: parent
        width: Math.min(window.width - 48, 480)
        title: qsTr("Remove fingerprint?")
        modal: true
        standardButtons: Controls.Dialog.Ok | Controls.Dialog.Cancel
        onAccepted: backend.delete(window.selectedFinger)
        contentItem: Controls.Label {
            text: qsTr("Remove the saved %1 fingerprint for %2? You will need to enroll this finger again to use it.").arg(window.fingerLabel(window.selectedFinger)).arg(backend.userName)
            wrapMode: Text.Wrap
        }
    }
    Connections {
        target: backend
        function onPamReviewReady() { pamDialog.open(); }
    }
    Controls.Dialog {
        id: pamDialog
        objectName: "pamDialog"
        onClosed: backend.cancelPamReview()
        anchors.centerIn: parent
        width: Math.min(window.width - 48, 720)
        title: backend.pamAction === "restore" ? qsTr("Return to external configuration: %1").arg(backend.pamTitle)
             : backend.pamAction === "adopt" ? qsTr("Manage configuration: %1").arg(backend.pamTitle)
             : qsTr("Review: %1").arg(backend.pamTitle)
        modal: true
        standardButtons: Controls.Dialog.Close
        contentItem: ColumnLayout {
            Controls.Label {
                text: qsTr("Target: %1").arg(backend.pamTarget)
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                font.bold: true
            }
            Controls.Label {
                text: backend.pamDetail
                Layout.fillWidth: true
                wrapMode: Text.Wrap
            }
            Controls.Label {
                text: backend.pamRequiresAdmin
                    ? qsTr("Only this service file can change. Included PAM files remain untouched. An administrator must authorize changes, and the original configuration is backed up.")
                    : qsTr("This changes only your KDE user preference. No administrator authorization or PAM edit is required. Your original user configuration is backed up first.")
                Layout.fillWidth: true
                wrapMode: Text.Wrap
            }
            Kirigami.InlineMessage {
                Layout.fillWidth: true
                visible: backend.pamRequiresAdmin && !backend.helperReady
                text: qsTr("The administrator helper is not installed. You can review this change, but applying it requires installing the system package with its helper and PolicyKit policy.")
                type: Kirigami.MessageType.Information
            }
            Controls.ScrollView {
                Layout.fillWidth: true
                Layout.preferredHeight: 250
                Controls.TextArea { objectName: "pamPreviewText"; text: backend.pamPreview; readOnly: true; selectByMouse: true; font.family: "monospace"; wrapMode: TextEdit.Wrap }
            }
            Controls.Button {
                objectName: "applyPamButton"
                text: !backend.pamRequiresAdmin ? (backend.pamAction === "disable" ? qsTr("Disable for my account") : qsTr("Enable for my account"))
                      : backend.pamAction === "restore" ? (backend.pamWaitingConfirmation ? qsTr("Restore external configuration") : qsTr("Authorize and restore external configuration"))
                      : backend.pamAction === "adopt" ? qsTr("Authorize management")
                      : backend.pamAction === "disable" ? (backend.pamWaitingConfirmation ? qsTr("Disable fingerprint") : qsTr("Authorize and disable"))
                      : backend.pamWaitingConfirmation ? qsTr("Enable fingerprint") : qsTr("Authorize and enable")
                icon.name: "dialog-password"
                enabled: (!backend.busy || backend.pamWaitingConfirmation) && backend.pamCanApply && (backend.helperReady || !backend.pamRequiresAdmin)
                onClicked: { backend.configurePam(); pamDialog.close(); }
            }
        }
    }
}
