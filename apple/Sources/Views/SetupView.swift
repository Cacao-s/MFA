import SwiftUI

/// First run, and the way back in after a reset.
struct SetupView: View {
    @EnvironmentObject private var model: AppModel
    @State private var isImporting = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundStyle(.tint)

            VStack(spacing: 8) {
                Text("MFA").font(.largeTitle.bold())
                Text("Your verification codes, encrypted on this device.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 12) {
                Button("Start fresh") { model.createVault() }
                    .buttonStyle(.borderedProminent)

                Button("Restore from a backup") { isImporting = true }
                    .buttonStyle(.bordered)
            }

            Text("""
            Codes are generated on this device and never sent anywhere. \
            Set up sync later if you want them on more than one device.
            """)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        }
        .padding(32)
        .sheet(isPresented: $isImporting) {
            // Restoring needs a vault to merge into, so make one first.
            RestoreFirstRunView()
        }
    }
}

/// Restoring on a device with no vault yet: create, then import.
private struct RestoreFirstRunView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        BackupView(mode: .importOnly) {
            dismiss()
        }
        .task {
            if model.phase == .needsSetup { model.createVault() }
        }
    }
}
