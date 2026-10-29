import Foundation
import Security

/// The Keychain, holding the two 32-byte keys the core needs.
///
/// This is `mfa_core::platform::SecureStore` on Apple platforms, and it is the
/// one thing in the app that must not be faked with a file: the security model
/// rests on the OS holding the key.
///
/// Both items are `WhenUnlockedThisDeviceOnly`, which keeps them out of iCloud
/// Keychain and out of an encrypted device backup, so restoring a backup onto a
/// second phone does not bring the accounts with it. That is the behaviour we
/// want: moving to a new device goes through the encrypted backup file or a
/// sync target, both of which ask for the password.
///
/// There is deliberately no `SecAccessControl` on the items. With
/// `.biometryCurrentSet` a user who adds a fingerprint loses their vault, and
/// with `.userPresence` every read prompts, which would mean a prompt on every
/// save. The unlock gate is `Biometrics` instead, which already falls back to
/// the device passcode.
enum KeychainStore {
    enum Key: String {
        /// Encrypts the local vault file.
        case vaultData = "vault-data-key"
        /// Shared by every device in the sync set.
        case sync = "sync-key"
    }

    enum Failure: LocalizedError {
        case unexpectedStatus(OSStatus)
        case wrongSize(Int)

        var errorDescription: String? {
            switch self {
            case let .unexpectedStatus(status):
                let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
                return "The keychain returned an error: \(message) (\(status))."
            case let .wrongSize(size):
                return "The stored key is \(size) bytes; it should be 32."
            }
        }
    }

    private static let service = "com.zeyanlin.mfa"

    /// Reads a key, or `nil` on a fresh install.
    static func load(_ key: Key) throws -> Data? {
        var query = baseQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { throw Failure.unexpectedStatus(status) }
            guard data.count == 32 else { throw Failure.wrongSize(data.count) }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw Failure.unexpectedStatus(status)
        }
    }

    /// Stores a key, replacing any existing one.
    static func store(_ key: Key, _ value: Data) throws {
        precondition(value.count == 32, "a key is 32 bytes")

        // Update in place when it is already there, so the item's attributes
        // are not quietly reset by a delete-and-add.
        let update = [kSecValueData as String: value]
        let status = SecItemUpdate(baseQuery(key) as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw Failure.unexpectedStatus(status) }

        var item = baseQuery(key)
        item[kSecValueData as String] = value
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { throw Failure.unexpectedStatus(added) }
    }

    /// Removes a key. Removing the vault key makes the vault file unreadable,
    /// which is what "reset the app" means.
    static func delete(_ key: Key) throws {
        let status = SecItemDelete(baseQuery(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.unexpectedStatus(status)
        }
    }

    // MARK: - sync target credentials

    /// Reads a sync target's token.
    ///
    /// Tokens live here and never in the vault: the vault's settings travel to
    /// the other devices, and a GitHub token must not.
    static func loadToken(targetID: String) throws -> String? {
        guard let data = try loadRaw(account: "token-\(targetID)") else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func storeToken(targetID: String, _ token: String) throws {
        try storeRaw(account: "token-\(targetID)", Data(token.utf8))
    }

    static func deleteToken(targetID: String) throws {
        try deleteRaw(account: "token-\(targetID)")
    }

    // MARK: - raw items

    private static func loadRaw(account: String) throws -> Data? {
        var query = query(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess: return item as? Data
        case errSecItemNotFound: return nil
        default: throw Failure.unexpectedStatus(status)
        }
    }

    private static func storeRaw(account: String, _ value: Data) throws {
        let update = [kSecValueData as String: value]
        let status = SecItemUpdate(query(account: account) as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw Failure.unexpectedStatus(status) }

        var item = query(account: account)
        item[kSecValueData as String] = value
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(item as CFDictionary, nil)
        guard added == errSecSuccess else { throw Failure.unexpectedStatus(added) }
    }

    private static func deleteRaw(account: String) throws {
        let status = SecItemDelete(query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.unexpectedStatus(status)
        }
    }

    private static func baseQuery(_ key: Key) -> [String: Any] {
        query(account: key.rawValue)
    }

    private static func query(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            // Not synchronizable: see the type's documentation.
            kSecAttrSynchronizable as String: false,
        ]
    }
}
