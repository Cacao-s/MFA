namespace MFA.Sync;

/// <summary>
/// One place a copy of the vault is kept.
/// </summary>
/// <remarks>
/// This is <c>mfa_core::platform::SyncProvider</c>. The core never calls it —
/// its <c>sync</c> takes and returns bytes — so this is free to be async in
/// the way .NET actually wants.
/// <para/>
/// The revision is whatever the target uses to detect a concurrent write: an
/// ETag, a blob SHA, a commit id. It matters because the sync file is opaque
/// ciphertext that no target can merge, so a write has to fail rather than
/// clobber a revision we have not merged.
/// </remarks>
internal interface ISyncProvider
{
    /// <summary>Downloads the file, or null if it is not there yet.</summary>
    Task<Fetched?> FetchAsync(string name);

    /// <summary>
    /// Uploads, only if the remote is still at <paramref name="expected"/>
    /// (null meaning "only if it does not exist yet").
    /// </summary>
    /// <returns>
    /// The new revision, or null when the remote moved — which tells the
    /// caller to fetch, merge and try again.
    /// </returns>
    Task<string?> PutAsync(string name, byte[] bytes, string? expected);
}

internal sealed record Fetched(byte[] Bytes, string Revision);

/// <summary>The two file names a sync set uses.</summary>
internal static class SyncFile
{
    internal const string Vault = "mfa-sync.vault";
    internal const string Key = "mfa-sync.key";
}

internal sealed class SyncProblem(string message) : Exception(message);
