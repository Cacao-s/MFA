import Foundation

/// Where the encrypted vault file lives, and how it is written.
///
/// This is `mfa_core::platform::VaultStorage` on Apple platforms. The write is
/// atomic because a vault truncated half way through is a vault that no longer
/// decrypts, and the user's accounts are not recoverable from it.
struct VaultStore {
    enum Failure: LocalizedError {
        case noApplicationSupportDirectory

        var errorDescription: String? {
            "The app could not find its own storage directory."
        }
    }

    let fileURL: URL

    /// `~/Library/Application Support/MFA/vault.mfa`, in the app container.
    init() throws {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                                  in: .userDomainMask).first
        else { throw Failure.noApplicationSupportDirectory }

        let directory = base.appendingPathComponent("MFA", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.fileURL = directory.appendingPathComponent("vault.mfa", isDirectory: false)
    }

    var exists: Bool {
        FileManager.default.fileExists(atPath: fileURL.path)
    }

    func read() throws -> Data? {
        exists ? try Data(contentsOf: fileURL) : nil
    }

    /// Writes the vault, atomically.
    ///
    /// `.atomic` writes a temporary file and renames it, so a crash or a full
    /// disk leaves the previous vault intact rather than a half-written one.
    func write(_ bytes: Data) throws {
        try bytes.write(to: fileURL, options: [.atomic])

        #if os(iOS)
        // Unreadable until the device is first unlocked after a boot, which
        // matches where the key lives.
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: fileURL.path
        )
        #endif

        // Nothing here belongs in a cloud backup: the key is device-only, so a
        // restored copy of the ciphertext would be useless anyway, and leaving
        // it out keeps the attack surface small.
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var url = fileURL
        try? url.setResourceValues(resourceValues)
    }

    /// Deletes the vault file. Used when the user resets the app.
    func removeFile() throws {
        guard exists else { return }
        try FileManager.default.removeItem(at: fileURL)
    }
}
