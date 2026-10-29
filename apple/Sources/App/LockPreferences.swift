import Foundation

/// The handful of lock settings the app needs to know *before* the vault is
/// open.
///
/// The real settings live in the vault, so they travel between devices. But the
/// vault cannot be read until the app is unlocked, and deciding whether to show
/// the lock screen is exactly the thing that happens first. So the two values
/// that decision needs are mirrored here, outside the vault, and rewritten
/// whenever the vault's settings change.
///
/// Neither is secret: whether the app locks, and after how long.
enum LockPreferences {
    private static let lockEnabledKey = "lock-enabled"
    private static let timeoutKey = "lock-background-timeout-secs"

    static var isLockEnabled: Bool {
        get {
            // Default on: a fresh install should lock, not be open.
            UserDefaults.standard.object(forKey: lockEnabledKey) as? Bool ?? true
        }
        set { UserDefaults.standard.set(newValue, forKey: lockEnabledKey) }
    }

    static var backgroundTimeout: TimeInterval {
        get {
            let stored = UserDefaults.standard.integer(forKey: timeoutKey)
            return stored > 0 ? TimeInterval(stored) : 30
        }
        set { UserDefaults.standard.set(Int(newValue), forKey: timeoutKey) }
    }

    /// Copies the vault's settings into the mirror.
    static func mirror(_ config: LockConfig) {
        isLockEnabled = config.biometricEnabled
        backgroundTimeout = TimeInterval(config.backgroundTimeoutSecs)
    }
}
