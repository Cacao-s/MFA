import SwiftUI

/// The lock screen.
///
/// The gate is the OS's own: Face ID, Touch ID, or the device passcode. The
/// vault's PIN is not offered here — see `Biometrics` for why — except on a
/// device with no biometrics and no passcode, where there is nothing else.
struct LockView: View {
    @EnvironmentObject private var model: AppModel
    @State private var isWorking = false

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundStyle(.tint)

            Text("MFA is locked").font(.title2.weight(.semibold))

            Button {
                Task {
                    isWorking = true
                    await model.unlock()
                    isWorking = false
                }
            } label: {
                if isWorking {
                    ProgressView()
                } else {
                    Text(buttonTitle)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(isWorking)
        }
        .padding(32)
        // Prompt straight away: making the user tap first is a step for
        // nothing, and cancelling still leaves the button.
        .task { await model.unlock() }
    }

    private var icon: String {
        switch model.lockCapability {
        case let .biometrics(name): name == "Face ID" ? "faceid" : "touchid"
        case .passcodeOnly: "lock"
        case .none: "lock.open"
        }
    }

    private var buttonTitle: String {
        switch model.lockCapability {
        case let .biometrics(name): "Unlock with \(name)"
        case .passcodeOnly: "Unlock"
        case .none: "Open"
        }
    }
}
