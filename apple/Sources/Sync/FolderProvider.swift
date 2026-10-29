import Foundation

/// A folder the OS already syncs: iCloud Drive, Google Drive, OneDrive, or any
/// directory the user picked.
///
/// There is no server here to hand out revisions, so the revision is the file's
/// own content hash. That is enough for the guarantee the sync round needs —
/// "has this changed since I read it?" — and it is the same answer on every
/// device, which a modification date is not.
///
/// It cannot be made truly atomic against another device writing at the same
/// instant through a file-syncing service; nothing at this layer can. What it
/// does guarantee is that we never overwrite a revision we have not merged,
/// which turns a lost write into a retry instead of lost accounts.
struct FolderProvider: SyncProvider {
    let directory: URL

    func fetch(_ name: String) async throws -> (bytes: Data, revision: String)? {
        let url = directory.appendingPathComponent(name, isDirectory: false)

        // A cloud folder may hold a placeholder that has not been materialised
        // yet; asking for it starts the download.
        if FileManager.default.isUbiquitousItem(at: url) {
            try? FileManager.default.startDownloadingUbiquitousItem(at: url)
        }
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }

        let bytes = try Data(contentsOf: url)
        return (bytes, Revision.of(bytes))
    }

    func put(_ name: String, bytes: Data, ifRevision expected: String?) async throws -> String? {
        let url = directory.appendingPathComponent(name, isDirectory: false)
        let current = FileManager.default.fileExists(atPath: url.path)
            ? Revision.of(try Data(contentsOf: url))
            : nil

        guard current == expected else { return nil }

        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try bytes.write(to: url, options: [.atomic])
        return Revision.of(bytes)
    }
}
