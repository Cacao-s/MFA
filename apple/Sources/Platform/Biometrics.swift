import Foundation
import LocalAuthentication

/// The app-lock gate: Face ID, Touch ID, or the device passcode.
///
/// This is `mfa_core::platform::BiometricAuth` on Apple platforms. It uses
/// `.deviceOwnerAuthentication` rather than `.deviceOwnerAuthenticationWithBiometrics`
/// on purpose: that policy already falls back to the device passcode when a
/// face is not recognised or a finger is wet, so the user always has a way in
/// and the app does not need a PIN of its own to be the fallback.
///
/// The vault's own PIN (`VaultHandle.setPin`) is therefore not the unlock
/// gate here. It is a re-authentication step for the few actions that deserve
/// one — revealing a secret, exporting a backup, changing sync — which is
/// worth having and does not fight the platform. See `apple/README.md`.
enum Biometrics {
    enum Capability {
        /// Face ID or Touch ID is set up.
        case biometrics(String)
        /// No biometrics, but there is a passcode.
        case passcodeOnly
        /// Nothing: no biometrics and no passcode. The app cannot lock.
        case none
    }

    enum Outcome {
        case succeeded
        /// The user dismissed the prompt. Not a failure; do not nag.
        case cancelled
        /// Authentication failed or is locked out, with something to show.
        case failed(String)
    }

    static func capability() -> Capability {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return .biometrics(name(for: context.biometryType))
        }
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return .passcodeOnly
        }
        return .none
    }

    /// Prompts the user. `reason` is shown by the OS, so it has to read as a
    /// sentence and be localised.
    static func authenticate(reason: String) async -> Outcome {
        let context = LAContext()
        // The OS's own wording for the fallback button is right; ours would
        // only be a worse translation.
        context.localizedFallbackTitle = nil

        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthentication,
                                                      localizedReason: reason)
            return ok ? .succeeded : .failed("Authentication did not succeed.")
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel:
                return .cancelled
            case .userFallback:
                // Only reachable if a fallback title is set; treated as a
                // cancel so the caller shows its own options.
                return .cancelled
            default:
                return .failed(error.localizedDescription)
            }
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    private static func name(for type: LABiometryType) -> String {
        switch type {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        default: "biometrics"
        }
    }
}
