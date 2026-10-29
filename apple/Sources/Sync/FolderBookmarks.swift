import Foundation

/// Remembers a sync folder across launches.
///
/// A sandboxed app loses access to a user-chosen directory when it quits, so
/// the choice has to be stored as a security-scoped bookmark rather than as a
/// path. The bookmark is not a secret — it says where, not what — so
/// `UserDefaults` is the right place for it; the vault inside the folder is
/// encrypted regardless.
enum FolderBookmarks {
    private static func key(_ targetID: String) -> String { "sync-folder-\(targetID)" }

    /// Stores the user's choice.
    static func remember(targetID: String, url: URL) throws {
        #if os(macOS)
        let data = try url.bookmarkData(options: [.withSecurityScope],
                                        includingResourceValuesForKeys: nil,
                                        relativeTo: nil)
        #else
        let data = try url.bookmarkData(options: [],
                                        includingResourceValuesForKeys: nil,
                                        relativeTo: nil)
        #endif
        UserDefaults.standard.set(data, forKey: key(targetID))
    }

    /// Resolves it again, or `nil` if the folder has gone.
    ///
    /// Starts access and does not stop it: the folder is used for the lifetime
    /// of the app, and stopping it after each sync would mean re-resolving on
    /// every round.
    static func resolve(targetID: String) -> URL? {
        guard let data = UserDefaults.standard.data(forKey: key(targetID)) else { return nil }

        var stale = false
        #if os(macOS)
        let options: URL.BookmarkResolutionOptions = [.withSecurityScope]
        #else
        let options: URL.BookmarkResolutionOptions = []
        #endif

        guard let url = try? URL(resolvingBookmarkData: data,
                                 options: options,
                                 relativeTo: nil,
                                 bookmarkDataIsStale: &stale)
        else { return nil }

        #if os(macOS)
        guard url.startAccessingSecurityScopedResource() else { return nil }
        #endif

        // A stale bookmark still resolves; refresh it so it keeps working.
        if stale { try? remember(targetID: targetID, url: url) }
        return url
    }

    static func forget(targetID: String) {
        UserDefaults.standard.removeObject(forKey: key(targetID))
    }
}
