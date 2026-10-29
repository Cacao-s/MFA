import Foundation

/// One place a copy of the vault is kept.
///
/// This is `mfa_core::platform::SyncProvider`. The core never calls it: the
/// core's `sync` takes and returns bytes, so this is free to be async in the
/// way the platform actually wants.
///
/// `revision` is whatever the target uses to detect a concurrent write — an
/// ETag, a blob SHA, a commit id. It matters because the sync file is opaque
/// ciphertext that no target can merge: a write has to fail rather than
/// clobber a revision we have not merged.
protocol SyncProvider: Sendable {
    /// Downloads the file, or `nil` if it is not there yet.
    func fetch(_ name: String) async throws -> (bytes: Data, revision: String)?

    /// Uploads, only if the remote is still at `expected` (`nil` meaning "only
    /// if it does not exist yet").
    ///
    /// Returns the new revision, or `nil` when the remote moved — which tells
    /// the caller to fetch, merge and try again.
    func put(_ name: String, bytes: Data, ifRevision expected: String?) async throws -> String?
}

/// The two file names a sync set uses.
enum SyncFile {
    static let vault = "mfa-sync.vault"
    static let key = "mfa-sync.key"
}

enum SyncProviderError: LocalizedError {
    case notConfigured(String)
    case missingCredential(String)
    case server(Int, String)

    var errorDescription: String? {
        switch self {
        case let .notConfigured(detail):
            "This sync target is not set up properly: \(detail)"
        case let .missingCredential(label):
            "No token is saved for “\(label)”. Add it again in Settings."
        case let .server(status, detail):
            detail.isEmpty ? "The server answered \(status)." : "The server answered \(status): \(detail)"
        }
    }
}
