import Foundation
import SwiftUI

/// The one piece of state the whole app reads.
///
/// It owns the open vault and nothing else owns a `VaultHandle`, so there is a
/// single place where "change something, then seal and write" happens. Every
/// mutation goes through `mutate`, which means a change can never be left
/// unsaved by a code path that forgot.
@MainActor
final class AppModel: ObservableObject {
    enum Phase: Equatable {
        /// Working out what we have.
        case loading
        /// No vault file: first run.
        case needsSetup
        /// There is a vault, and it is not open.
        case locked
        case unlocked
    }

    /// Something to show the user, with enough structure to act on.
    struct Alert: Identifiable {
        let id = UUID()
        var title: String
        var message: String
        /// Set when the right answer is to ask for the password again.
        var isWrongPassword = false
    }

    @Published private(set) var phase: Phase = .loading
    @Published private(set) var accounts: [AccountView] = []
    @Published var query: String = ""
    /// A short-lived line under the list: "Copied", "Synced 2 accounts".
    @Published private(set) var status: String?
    @Published var alert: Alert?
    @Published private(set) var isSyncing = false

    /// `nil` until the vault is open.
    private var vault: VaultHandle?
    private var store: VaultStore?
    private var ticker: Task<Void, Never>?
    private var statusReset: Task<Void, Never>?
    private var leftForeground: Date?

    var isLocked: Bool { phase == .locked }
    var lockCapability: Biometrics.Capability { Biometrics.capability() }

    // MARK: - lifecycle

    /// Works out whether this is a first run, and whether to lock.
    func start() {
        do {
            let store = try VaultStore()
            self.store = store

            guard store.exists else {
                phase = .needsSetup
                return
            }
            // There is a vault. If the lock is off we can open it straight
            // away; otherwise the lock screen asks first.
            if LockPreferences.isLockEnabled, case .none = Biometrics.capability() {
                // The device has no biometrics and no passcode, so there is
                // nothing to authenticate against. Opening is the only option
                // that is not "the user can never see their codes again".
                openVault()
            } else if LockPreferences.isLockEnabled {
                phase = .locked
            } else {
                openVault()
            }
        } catch {
            present(error, title: "Could not start")
            phase = .needsSetup
        }
    }

    /// First run: make a key, store it, and write an empty vault.
    func createVault() {
        guard let store else { return }
        do {
            let key = generateDataKey()
            // Store the key before sealing anything with it: the other order
            // leaves a vault file nothing can read.
            try KeychainStore.store(.vaultData, key)

            let vault = try VaultHandle.create(dataKey: key)
            try store.write(try vault.seal())
            adopt(vault)
        } catch {
            present(error, title: "Could not create your vault")
        }
    }

    /// Asks the OS to authenticate, then opens the vault.
    func unlock() async {
        let outcome = await Biometrics.authenticate(reason: "Unlock your verification codes")
        switch outcome {
        case .succeeded:
            openVault()
        case .cancelled:
            break
        case let .failed(message):
            alert = Alert(title: "Could not unlock", message: message)
        }
    }

    func lock() {
        ticker?.cancel()
        ticker = nil
        accounts = []
        query = ""
        vault = nil
        phase = .locked
    }

    /// Called when the app stops being frontmost.
    func enteredBackground() {
        leftForeground = Date()
    }

    /// Called when the app comes back. Re-locks if it was away long enough.
    func enteredForeground() {
        guard phase == .unlocked, LockPreferences.isLockEnabled else { return }
        guard let left = leftForeground else { return }
        leftForeground = nil

        if Date().timeIntervalSince(left) >= LockPreferences.backgroundTimeout {
            lock()
        }
    }

    private func openVault() {
        guard let store else { return }
        do {
            guard let key = try KeychainStore.load(.vaultData) else {
                // The file is there but the key is gone: an OS restore onto a
                // new device, or a keychain reset. The ciphertext is useless
                // now, and saying so is better than an unexplained failure.
                alert = Alert(
                    title: "This vault cannot be opened",
                    message: """
                    Its key was stored only on the device it was created on, and \
                    it is no longer there. Restore from an encrypted backup or a \
                    sync target to get your accounts back.
                    """
                )
                phase = .needsSetup
                return
            }
            guard let file = try store.read() else {
                phase = .needsSetup
                return
            }
            adopt(try VaultHandle.open(dataKey: key, file: file))
        } catch {
            present(error, title: "Could not open your vault")
        }
    }

    private func adopt(_ vault: VaultHandle) {
        self.vault = vault
        LockPreferences.mirror(vault.lockConfig())
        phase = .unlocked
        refresh()
        startTicking()
    }

    /// Recomputes the list once a second, so the codes and the countdown rings
    /// stay right without every row owning a timer.
    private func startTicking() {
        ticker?.cancel()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self else { return }
                await MainActor.run { self.refresh() }
            }
        }
    }

    private func refresh() {
        guard let vault else { return }
        let now = UInt64(Date().timeIntervalSince1970)
        do {
            accounts = query.trimmingCharacters(in: .whitespaces).isEmpty
                ? try vault.accounts(nowSecs: now)
                : try vault.search(query: query, nowSecs: now)
        } catch {
            present(error, title: "Could not read your accounts")
        }
    }

    /// Re-runs the search when the query changes.
    func queryChanged() { refresh() }

    // MARK: - mutations

    /// Runs a change and saves, or reports why it could not.
    ///
    /// Everything that writes goes through here: that is what guarantees a
    /// change is never left only in memory.
    private func mutate(_ title: String, _ change: (VaultHandle) throws -> Void) {
        guard let vault, let store else { return }
        do {
            try change(vault)
            try store.write(try vault.seal())
            LockPreferences.mirror(vault.lockConfig())
            refresh()
        } catch {
            present(error, title: title)
        }
    }

    private var nowMs: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// Adds a scanned or pasted URI. Returns whether it was new.
    @discardableResult
    func add(uri: String) -> Bool {
        guard let vault else { return false }
        do {
            let existing = try vault.duplicateOfUri(uri: uri)
            mutate("Could not add that account") { _ = try $0.addUri(uri: uri, nowMs: nowMs) }
            if existing != nil {
                show("You already had that account")
                return false
            }
            show("Added")
            return true
        } catch {
            present(error, title: "Could not add that account")
            return false
        }
    }

    func add(draft: AccountDraft) {
        mutate("Could not add that account") { _ = try $0.addManual(draft: draft, nowMs: nowMs) }
        show("Added")
    }

    func delete(id: String) {
        mutate("Could not delete that account") { try $0.delete(id: id, nowMs: nowMs) }
    }

    func setNote(id: String, note: String?) {
        mutate("Could not save the note") { try $0.setNote(id: id, note: note, nowMs: nowMs) }
    }

    func rename(id: String, issuer: String?, account: String) {
        mutate("Could not rename that account") {
            try $0.rename(id: id, issuer: issuer, accountName: account, nowMs: nowMs)
        }
    }

    func move(from source: IndexSet, to destination: Int) {
        var ids = accounts.map(\.id)
        ids.move(fromOffsets: source, toOffset: destination)
        mutate("Could not reorder") { try $0.reorder(ids: ids, nowMs: nowMs) }
    }

    func copy(_ account: AccountView) {
        guard let vault else { return }
        let seconds = vault.preferences().clipboardClearSecs
        let willClear = Clipboard.copy(code: account.code, clearAfter: seconds)
        show(willClear ? "Copied — clears in \(seconds)s" : "Copied")
    }

    /// The `otpauth://` URI for a QR code to move the account elsewhere.
    ///
    /// This contains the secret, which is why it is a separate, deliberate
    /// call and not part of the list.
    func exportURI(id: String) -> String? {
        guard let vault else { return nil }
        do {
            return try vault.accountUri(id: id)
        } catch {
            present(error, title: "Could not read that account")
            return nil
        }
    }

    // MARK: - settings

    func lockConfig() -> LockConfig? { vault?.lockConfig() }
    func preferences() -> Preferences? { vault?.preferences() }
    func syncTargets() -> [SyncTargetView] { vault?.syncTargets() ?? [] }

    func setLockConfig(_ config: LockConfig) {
        mutate("Could not save the lock settings") { $0.setLockConfig(config: config, nowMs: nowMs) }
    }

    func setPreferences(_ preferences: Preferences) {
        mutate("Could not save your settings") {
            $0.setPreferences(preferences: preferences, nowMs: nowMs)
        }
    }

    func setPin(_ pin: String) {
        mutate("Could not set the PIN") { try $0.setPin(pin: pin, nowMs: nowMs) }
        show("PIN set")
    }

    func clearPin() {
        mutate("Could not remove the PIN") { $0.clearPin(nowMs: nowMs) }
    }

    func verifyPin(_ pin: String) -> Bool {
        vault?.verifyPin(pin: pin) ?? false
    }

    @discardableResult
    func upsertSyncTarget(_ target: SyncTargetView) -> String? {
        var newID: String?
        mutate("Could not save that sync target") {
            newID = try $0.upsertSyncTarget(target: target, nowMs: nowMs)
        }
        return newID
    }

    func removeSyncTarget(id: String) {
        mutate("Could not remove that sync target") {
            try $0.removeSyncTarget(id: id, nowMs: nowMs)
        }
        try? KeychainStore.deleteToken(targetID: id)
        FolderBookmarks.forget(targetID: id)
    }

    // MARK: - backup

    func exportBackup(password: String) -> Data? {
        guard let vault else { return nil }
        do {
            return try vault.exportBackup(password: password)
        } catch {
            present(error, title: "Could not export")
            return nil
        }
    }

    func importBackup(_ file: Data, password: String) {
        guard let vault, let store else { return }
        do {
            let summary = try vault.importBackup(file: file, password: password)
            // Only write once the import succeeded: the core leaves the vault
            // untouched on a wrong password, and so should the file.
            try store.write(try vault.seal())
            refresh()
            show(summary.added == 0
                 ? "Nothing new in that backup"
                 : "Restored \(summary.added) account\(summary.added == 1 ? "" : "s")")
        } catch {
            present(error, title: "Could not import")
        }
    }

    // MARK: - migration

    func importMigration(uris: [String]) {
        guard let vault else { return }
        do {
            let result = try vault.importMigration(uris: uris, nowMs: nowMs)
            try store?.write(try vault.seal())
            refresh()

            if result.skipped.isEmpty {
                show("Imported \(result.summary.added) account\(result.summary.added == 1 ? "" : "s")")
            } else {
                // Never silent: a user told nothing will assume everything
                // came across and find out when they cannot log in.
                let names = result.skipped.map { "\($0.displayName) — \($0.reason)" }
                alert = Alert(
                    title: "Imported \(result.summary.added), skipped \(result.skipped.count)",
                    message: names.joined(separator: "\n")
                )
            }
        } catch {
            present(error, title: "Could not import")
        }
    }

    // MARK: - sync

    func syncNow() async {
        guard let vault, let store, !isSyncing else { return }
        guard let syncKey = try? KeychainStore.load(.sync), let syncKey else {
            alert = Alert(title: "Sync is not set up",
                          message: "Add a sync target in Settings first.")
            return
        }

        isSyncing = true
        defer { isSyncing = false }

        let result = await SyncCoordinator(vault: vault, syncKey: syncKey).run()
        do {
            try store.write(try vault.seal())
        } catch {
            present(error, title: "Synced, but could not save locally")
            return
        }
        refresh()

        if let first = result.problems.first {
            alert = Alert(title: "Sync had a problem",
                          message: result.problems.count == 1
                            ? "\(first.label): \(first.message)"
                            : result.problems.map { "\($0.label): \($0.message)" }
                                .joined(separator: "\n"))
            return
        }
        show(summaryLine(result.summary))
    }

    /// Starts a new sync set on this device.
    func createSyncSet() {
        do {
            let key = newSyncKey()
            try KeychainStore.store(.sync, key)
            show("Sync set up on this device")
        } catch {
            present(error, title: "Could not set up sync")
        }
    }

    /// Joins an existing sync set using the key file on a target.
    func joinSyncSet(keyFile: Data, password: String) {
        do {
            let key = try unwrapSyncKey(keyFile: keyFile, password: password)
            try KeychainStore.store(.sync, key)
            show("This device has joined")
        } catch {
            present(error, title: "Could not join")
        }
    }

    /// Publishes the wrapped sync key to every enabled target, so another
    /// device can join. Returns a message when it could not.
    func publishKeyFile(password: String) async -> String? {
        guard let vault else { return "The vault is not open." }
        guard let key = ((try? KeychainStore.load(.sync)) ?? nil) else {
            return "Sync is not set up on this device yet."
        }
        do {
            try await SyncCoordinator(vault: vault, syncKey: key).publishKeyFile(password: password)
            show("Key file published")
            return nil
        } catch {
            if case let MfaError.Failed(_, message) = error { return message }
            return error.localizedDescription
        }
    }

    var hasSyncKey: Bool {
        ((try? KeychainStore.load(.sync)) ?? nil) != nil
    }

    private func summaryLine(_ summary: MergeSummary) -> String {
        guard summary.changed else { return "Already up to date" }
        var parts: [String] = []
        if summary.added > 0 { parts.append("\(summary.added) added") }
        if summary.updated > 0 { parts.append("\(summary.updated) updated") }
        if summary.deleted > 0 { parts.append("\(summary.deleted) removed") }
        if summary.deduped > 0 { parts.append("\(summary.deduped) duplicate\(summary.deduped == 1 ? "" : "s") merged") }
        return parts.isEmpty ? "Synced" : "Synced: " + parts.joined(separator: ", ")
    }

    // MARK: - reset

    /// Deletes everything on this device.
    ///
    /// Takes the key out of the Keychain as well as the file: leaving the key
    /// behind would mean a recovered file could still be read.
    func resetEverything() {
        lock()
        try? store?.removeFile()
        try? KeychainStore.delete(.vaultData)
        try? KeychainStore.delete(.sync)
        phase = .needsSetup
    }

    // MARK: - reporting

    private func show(_ message: String) {
        status = message
        statusReset?.cancel()
        statusReset = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, !Task.isCancelled else { return }
            await MainActor.run { self.status = nil }
        }
    }

    private func present(_ error: Error, title: String) {
        if case let MfaError.Failed(kind, message) = error {
            alert = Alert(title: title, message: message, isWrongPassword: kind == .wrongPassword)
        } else {
            alert = Alert(title: title, message: error.localizedDescription)
        }
    }
}
