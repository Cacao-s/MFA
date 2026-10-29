import SwiftUI

/// Settings. Everything here lives in the vault, so it travels to the other
/// devices, except where it says otherwise.
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var lock = LockConfig(biometricEnabled: true,
                                         backgroundTimeoutSecs: 30,
                                         hasPin: false)
    @State private var preferences = Preferences(clipboardClearSecs: 30, sort: .manual)
    @State private var isSettingPin = false
    @State private var isConfirmingReset = false

    var body: some View {
        Form {
            Section {
                Toggle("Lock MFA", isOn: $lock.biometricEnabled)
                    .onChange(of: lock.biometricEnabled) { _, _ in saveLock() }

                if lock.biometricEnabled {
                    Picker("Lock after", selection: $lock.backgroundTimeoutSecs) {
                        Text("Immediately").tag(UInt32(0))
                        Text("30 seconds").tag(UInt32(30))
                        Text("1 minute").tag(UInt32(60))
                        Text("5 minutes").tag(UInt32(300))
                    }
                    .onChange(of: lock.backgroundTimeoutSecs) { _, _ in saveLock() }
                }
            } header: {
                Text("Lock")
            } footer: {
                Text(lockFooter)
            }

            Section {
                if lock.hasPin {
                    Button("Change PIN…") { isSettingPin = true }
                    Button("Remove PIN", role: .destructive) { model.clearPin(); reload() }
                } else {
                    Button("Set a PIN…") { isSettingPin = true }
                }
            } header: {
                Text("PIN")
            } footer: {
                Text("""
                Asked for before revealing a secret key or exporting a backup. \
                It is not what unlocks the app — \(unlockName) does that, and \
                falls back to your device passcode.
                """)
            }

            Section {
                Picker("Clear the clipboard after", selection: $preferences.clipboardClearSecs) {
                    Text("15 seconds").tag(UInt32(15))
                    Text("30 seconds").tag(UInt32(30))
                    Text("1 minute").tag(UInt32(60))
                }
                .onChange(of: preferences.clipboardClearSecs) { _, _ in savePreferences() }

                Picker("Order", selection: $preferences.sort) {
                    Text("As I arranged them").tag(SortMode.manual)
                    Text("By service name").tag(SortMode.issuerAsc)
                }
                .onChange(of: preferences.sort) { _, _ in savePreferences() }
            } header: {
                Text("List")
            } footer: {
                #if os(macOS)
                Text("""
                On the Mac the clipboard is cleared by MFA itself, so it only \
                happens while MFA is still running.
                """)
                #else
                Text("On iPhone and iPad the system clears it, even if MFA is closed.")
                #endif
            }

            Section("Sync and backup") {
                NavigationLink("Sync") { SyncSettingsView() }
                NavigationLink("Backup") { BackupView(mode: .both) {} }
            }

            Section {
                Button("Delete everything on this device…", role: .destructive) {
                    isConfirmingReset = true
                }
            } footer: {
                Text("""
                Removes the vault and its key from this device. Accounts on other \
                devices and in backups are not touched. MFA version \(libraryVersion()).
                """)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .toolbar {
            #if os(iOS)
            ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            #endif
        }
        .onAppear(perform: reload)
        .sheet(isPresented: $isSettingPin) { SetPinView() }
        .confirmationDialog("Delete everything on this device?",
                            isPresented: $isConfirmingReset, titleVisibility: .visible) {
            Button("Delete", role: .destructive) {
                model.resetEverything()
                dismiss()
            }
        } message: {
            Text("""
            Your accounts will be gone from this device and cannot be recovered \
            from it. Make sure you have a backup, or that another device has them.
            """)
        }
    }

    private var unlockName: String {
        switch model.lockCapability {
        case let .biometrics(name): name
        case .passcodeOnly: "your device passcode"
        case .none: "the lock"
        }
    }

    private var lockFooter: String {
        switch model.lockCapability {
        case let .biometrics(name):
            "MFA asks for \(name), or your device passcode if that does not work."
        case .passcodeOnly:
            "MFA asks for your device passcode. Set up Face ID or Touch ID for something quicker."
        case .none:
            "This device has no passcode and no biometrics, so MFA cannot lock. Set a device passcode first."
        }
    }

    private func reload() {
        if let current = model.lockConfig() { lock = current }
        if let current = model.preferences() { preferences = current }
    }

    private func saveLock() { model.setLockConfig(lock) }
    private func savePreferences() { model.setPreferences(preferences) }
}

/// Setting the PIN, typed twice.
private struct SetPinView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var pin = ""
    @State private var again = ""

    private var problem: String? {
        if pin.count < 4 { return "At least 4 digits." }
        if !again.isEmpty, pin != again { return "The two do not match." }
        return nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("PIN", text: $pin)
                    SecureField("PIN again", text: $again)
                } footer: {
                    if let problem {
                        Text(problem).foregroundStyle(.red)
                    } else {
                        Text("Four digits or more.")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Set a PIN")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.setPin(pin)
                        dismiss()
                    }
                    .disabled(problem != nil || pin != again)
                }
            }
        }
    }
}
