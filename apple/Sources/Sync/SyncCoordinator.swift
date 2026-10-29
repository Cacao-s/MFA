import Foundation

/// Runs one sync round over every enabled target.
///
/// The core decides what the vault should become; this decides how the bytes
/// move. The shape is read, merge, write, retrying a target whose revision
/// moved while we were merging — never overwriting it, because the file is
/// opaque ciphertext that nothing can merge after the fact.
@MainActor
struct SyncCoordinator {
    /// How many times a single target may lose the race before we give up and
    /// leave it for the next sync. Three is enough for a real collision and
    /// small enough that a misbehaving server cannot spin here.
    private static let maxAttempts = 3

    struct Result {
        var summary: MergeSummary
        /// Targets that were written, by label.
        var written: [String] = []
        /// Targets that could not be reached or read, with something to show.
        var problems: [(label: String, message: String)] = []
    }

    let vault: VaultHandle
    let syncKey: Data

    /// Syncs every enabled target and returns what happened.
    ///
    /// Caller's job afterwards: seal the vault and write it locally. This does
    /// not touch the local file, so a failed sync cannot corrupt it.
    func run() async -> Result {
        let targets = vault.syncTargets().filter(\.enabled)
        var result = Result(summary: MergeSummary(added: 0, updated: 0, deleted: 0,
                                                  deduped: 0, changed: false))
        guard !targets.isEmpty else { return result }

        // Build the providers first, so a target with no token is reported
        // rather than silently skipped.
        var providers: [(target: SyncTargetView, provider: any SyncProvider)] = []
        for target in targets {
            do {
                providers.append((target, try provider(for: target)))
            } catch {
                result.problems.append((target.label, message(for: error)))
            }
        }

        var pending = providers
        var attempt = 0
        while !pending.isEmpty, attempt < Self.maxAttempts {
            attempt += 1
            var retry: [(target: SyncTargetView, provider: any SyncProvider)] = []

            // 1. Read every target.
            var revisions: [String: String?] = [:]
            var remotes: [RemoteFile] = []
            for (target, provider) in pending {
                do {
                    let fetched = try await provider.fetch(SyncFile.vault)
                    revisions[target.id] = fetched?.revision
                    remotes.append(RemoteFile(target: target.id, bytes: fetched?.bytes))
                } catch {
                    result.problems.append((target.label, message(for: error)))
                }
            }
            guard !remotes.isEmpty else { break }

            // 2. Merge them all at once: one round, one dedupe.
            let round: SyncRound
            do {
                round = try vault.sync(remotes: remotes, syncKey: syncKey)
            } catch {
                result.problems.append(("sync", message(for: error)))
                break
            }
            result.summary = accumulate(result.summary, round.summary)

            for failure in round.failures {
                let label = pending.first { $0.target.id == failure.target }?.target.label ?? failure.target
                result.problems.append((label, failure.message))
            }

            // 3. Write back to whichever targets are behind.
            for upload in round.uploads {
                guard let entry = pending.first(where: { $0.target.id == upload.target }) else { continue }
                do {
                    let written = try await entry.provider.put(
                        SyncFile.vault,
                        bytes: upload.bytes,
                        ifRevision: revisions[upload.target] ?? nil
                    )
                    if written == nil {
                        // Someone wrote first. Round again against what is
                        // there now rather than overwriting it.
                        retry.append(entry)
                    } else {
                        result.written.append(entry.target.label)
                    }
                } catch {
                    result.problems.append((entry.target.label, message(for: error)))
                }
            }

            pending = retry
        }

        if !pending.isEmpty {
            for entry in pending {
                result.problems.append((entry.target.label,
                                        "Another device kept writing first. It will try again on the next sync."))
            }
        }
        return result
    }

    /// Publishes the wrapped sync key so another device can join.
    func publishKeyFile(password: String) async throws {
        let wrapped = try wrapSyncKey(syncKey: syncKey, password: password)
        for target in vault.syncTargets().filter(\.enabled) {
            let provider = try provider(for: target)
            let existing = try await provider.fetch(SyncFile.key)
            _ = try await provider.put(SyncFile.key, bytes: wrapped, ifRevision: existing?.revision)
        }
    }

    /// Fetches the key file from the first target that has one, for a device
    /// joining an existing sync set.
    static func fetchKeyFile(targets: [SyncTargetView]) async throws -> Data? {
        for target in targets where target.enabled {
            let provider = try makeProvider(for: target)
            if let fetched = try await provider.fetch(SyncFile.key) {
                return fetched.bytes
            }
        }
        return nil
    }

    private func provider(for target: SyncTargetView) throws -> any SyncProvider {
        try Self.makeProvider(for: target)
    }

    private static func makeProvider(for target: SyncTargetView) throws -> any SyncProvider {
        switch target.kind {
        case .folder:
            guard let url = FolderBookmarks.resolve(targetID: target.id) else {
                throw SyncProviderError.notConfigured(
                    "the folder is no longer reachable; choose it again")
            }
            return FolderProvider(directory: url)

        case .gitHub, .gitLab, .server:
            guard let token = try KeychainStore.loadToken(targetID: target.id), !token.isEmpty else {
                throw SyncProviderError.missingCredential(target.label)
            }
            let flavour: HTTPProvider.Flavour = switch target.kind {
            case .gitHub: .gitHub
            case .gitLab: .gitLab
            default: .selfHosted
            }
            return HTTPProvider(flavour: flavour, location: target.location, token: token)
        }
    }

    private func accumulate(_ total: MergeSummary, _ round: MergeSummary) -> MergeSummary {
        MergeSummary(
            added: total.added + round.added,
            updated: total.updated + round.updated,
            deleted: total.deleted + round.deleted,
            deduped: total.deduped + round.deduped,
            changed: total.changed || round.changed
        )
    }

    private func message(for error: Error) -> String {
        if case let MfaError.Failed(_, message) = error { return message }
        return error.localizedDescription
    }
}
