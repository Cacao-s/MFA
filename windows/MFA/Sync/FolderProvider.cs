using System.Security.Cryptography;

namespace MFA.Sync;

/// <summary>
/// A folder the user picked — OneDrive, Google Drive, Dropbox, or any
/// directory.
/// </summary>
/// <remarks>
/// There is no server here to hand out revisions, so the revision is the
/// file's own content hash. That answers the only question the sync round asks
/// — "has this changed since I read it?" — and gives the same answer on every
/// device, which a modification time does not.
/// <para/>
/// It cannot be atomic against another device writing at the same instant
/// through a syncing client; nothing at this layer can. What it does guarantee
/// is that we never overwrite a revision we have not merged, which turns a
/// lost write into a retry rather than lost accounts.
/// </remarks>
internal sealed class FolderProvider(string directory) : ISyncProvider
{
    public Task<Fetched?> FetchAsync(string name)
    {
        var path = Path.Combine(directory, name);
        if (!File.Exists(path)) return Task.FromResult<Fetched?>(null);

        var bytes = File.ReadAllBytes(path);
        return Task.FromResult<Fetched?>(new Fetched(bytes, Hash(bytes)));
    }

    public Task<string?> PutAsync(string name, byte[] bytes, string? expected)
    {
        var path = Path.Combine(directory, name);
        var current = File.Exists(path) ? Hash(File.ReadAllBytes(path)) : null;
        if (current != expected) return Task.FromResult<string?>(null);

        Directory.CreateDirectory(directory);

        var temporary = path + ".tmp";
        File.WriteAllBytes(temporary, bytes);
        if (File.Exists(path)) File.Replace(temporary, path, destinationBackupFileName: null);
        else File.Move(temporary, path);

        return Task.FromResult<string?>(Hash(bytes));
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
