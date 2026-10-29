namespace MFA.Core;

/// <summary>
/// An open vault.
/// </summary>
/// <remarks>
/// A typed face over the JSON bus, so the rest of the app never writes a
/// method name or a parameter object. The core is free of I/O on purpose, and
/// that stays true here: this holds the decrypted vault and its key in memory,
/// and the app does every bit of reading, writing and networking.
/// <para/>
/// Time is always passed in — <c>nowMs</c> for edits, <c>nowSecs</c> for codes
/// — so the vault never reads a clock and the same call is reproducible.
/// </remarks>
internal sealed class VaultHandle : IDisposable
{
    private ulong _handle;
    private bool _closed;

    private VaultHandle(ulong handle) => _handle = handle;

    /// <summary>An empty vault, for a first run.</summary>
    /// <remarks>
    /// The key has to be in protected storage before the vault is sealed with
    /// it, or the file will not be readable again.
    /// </remarks>
    internal static VaultHandle Create(byte[] dataKey) =>
        new(MfaCore.Call<Opened>("create", new { data_key = dataKey }).Handle);

    /// <summary>Opens a vault file the app read.</summary>
    internal static VaultHandle Open(byte[] dataKey, byte[] file) =>
        new(MfaCore.Call<Opened>("open", new { data_key = dataKey, file }).Handle);

    /// <summary>
    /// The encrypted vault, to be written back by the app.
    /// </summary>
    /// <remarks>
    /// Write it atomically — temporary file, then replace — or a crash during
    /// the write can leave a vault that no longer decrypts.
    /// </remarks>
    internal byte[] Seal() => Call<byte[]>("seal");

    internal uint Count() => Call<uint>("count");

    internal AccountView[] Accounts(ulong nowSecs) =>
        Call<AccountView[]>("accounts", new { now_secs = nowSecs });

    internal AccountView[] Search(string query, ulong nowSecs) =>
        Call<AccountView[]>("search", new { query, now_secs = nowSecs });

    internal string Code(string id, ulong nowSecs) =>
        Call<string>("code", new { id, now_secs = nowSecs });

    /// <summary>
    /// The account as an <c>otpauth://</c> URI.
    /// </summary>
    /// <remarks>
    /// <b>This contains the secret.</b> It is what a "move this to another app"
    /// screen needs, and should not be used for anything else — not logged, not
    /// put on the clipboard without asking.
    /// </remarks>
    internal string AccountUri(string id) => Call<string>("account_uri", new { id });

    internal string AddUri(string uri, long nowMs) =>
        Call<string>("add_uri", new { uri, now_ms = nowMs });

    /// <summary>The id of an account identical to this URI's, if any.</summary>
    internal string? DuplicateOfUri(string uri) =>
        Call<string?>("duplicate_of_uri", new { uri });

    internal string AddManual(AccountDraft draft, long nowMs) =>
        Call<string>("add_manual", new { draft, now_ms = nowMs });

    internal void SetNote(string id, string? note, long nowMs) =>
        Invoke("set_note", new { id, note, now_ms = nowMs });

    internal void Rename(string id, string? issuer, string account, long nowMs) =>
        Invoke("rename", new { id, issuer, account, now_ms = nowMs });

    internal void Delete(string id, long nowMs) =>
        Invoke("delete", new { id, now_ms = nowMs });

    internal void Reorder(IEnumerable<string> ids, long nowMs) =>
        Invoke("reorder", new { ids, now_ms = nowMs });

    internal uint PruneTombstones(long nowMs) =>
        Call<uint>("prune_tombstones", new { now_ms = nowMs });

    internal ImportResult ImportMigration(IEnumerable<string> uris, long nowMs) =>
        Call<ImportResult>("import_migration", new { uris, now_ms = nowMs });

    internal byte[] ExportBackup(string password) =>
        Call<byte[]>("export_backup", new { password });

    internal MergeSummary ImportBackup(byte[] file, string password) =>
        Call<MergeSummary>("import_backup", new { file, password });

    internal LockConfig LockConfig() => Call<LockConfig>("lock_config");

    internal void SetLockConfig(LockConfig config, long nowMs) =>
        Invoke("set_lock_config", new { config, now_ms = nowMs });

    internal void SetPin(string pin, long nowMs) =>
        Invoke("set_pin", new { pin, now_ms = nowMs });

    internal void ClearPin(long nowMs) => Invoke("clear_pin", new { now_ms = nowMs });

    internal bool VerifyPin(string pin) => Call<bool>("verify_pin", new { pin });

    internal Preferences Preferences() => Call<Preferences>("preferences");

    internal void SetPreferences(Preferences preferences, long nowMs) =>
        Invoke("set_preferences", new { preferences, now_ms = nowMs });

    internal SyncTargetView[] SyncTargets() => Call<SyncTargetView[]>("sync_targets");

    internal string UpsertSyncTarget(SyncTargetView target, long nowMs) =>
        Call<string>("upsert_sync_target", new { target, now_ms = nowMs });

    internal void RemoveSyncTarget(string id, long nowMs) =>
        Invoke("remove_sync_target", new { id, now_ms = nowMs });

    /// <summary>One sync round against every target the app fetched.</summary>
    /// <remarks>
    /// Write each returned upload back <b>guarded by the revision it was read
    /// at</b>; if a write is refused because the revision moved, fetch again
    /// and call this again. Nothing comes back for a target whose file could
    /// not be opened: it may belong to another sync set.
    /// </remarks>
    internal SyncRound Sync(IEnumerable<RemoteFile> remotes, byte[] syncKey) =>
        Call<SyncRound>("sync", new { remotes, sync_key = syncKey });

    public void Dispose()
    {
        if (_closed) return;
        _closed = true;
        // Drops the vault and its key on the Rust side.
        try { MfaCore.Invoke("close", handle: _handle); } catch (MfaException) { }
        _handle = 0;
    }

    private T Call<T>(string method, object? parameters = null)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        return MfaCore.Call<T>(method, parameters, _handle);
    }

    private void Invoke(string method, object? parameters = null)
    {
        ObjectDisposedException.ThrowIf(_closed, this);
        MfaCore.Invoke(method, parameters, _handle);
    }

    private sealed record Opened(ulong Handle);
}

/// <summary>The calls that do not need an open vault.</summary>
internal static class Mfa
{
    /// <summary>
    /// A fresh 32-byte vault data key.
    /// </summary>
    /// <remarks>
    /// Put it in protected storage <b>before</b> sealing a vault with it: if it
    /// is lost, the vault file cannot be read again.
    /// </remarks>
    internal static byte[] GenerateDataKey() => MfaCore.Call<byte[]>("generate_data_key");

    /// <summary>A fresh sync key, for the first device in a new sync set.</summary>
    internal static byte[] NewSyncKey() => MfaCore.Call<byte[]>("new_sync_key");

    /// <summary>
    /// Wraps the sync key with the user's password, for the key file other
    /// devices read to join. This is the same password as the backup password.
    /// </summary>
    internal static byte[] WrapSyncKey(byte[] syncKey, string password) =>
        MfaCore.Call<byte[]>("wrap_sync_key", new { sync_key = syncKey, password });

    internal static byte[] UnwrapSyncKey(byte[] keyFile, string password) =>
        MfaCore.Call<byte[]>("unwrap_sync_key", new { key_file = keyFile, password });

    /// <summary>
    /// What a scanned or pasted URI holds, for a confirmation screen.
    /// Without the secret: a confirmation screen has no use for it.
    /// </summary>
    internal static UriPreview PreviewUri(string uri) =>
        MfaCore.Call<UriPreview>("preview_uri", new { uri });

    /// <summary>
    /// How far through a Google Authenticator export the scanned URIs get, so
    /// the UI can say "scan code 2 of 3". Nothing is remembered in the core;
    /// pass them all each time.
    /// </summary>
    internal static MigrationProgress MigrationProgress(IEnumerable<string> uris) =>
        MfaCore.Call<MigrationProgress>("migration_progress", new { uris });

    internal static BackupInfo InspectBackup(byte[] file) =>
        MfaCore.Call<BackupInfo>("inspect_backup", new { file });

    /// <summary>
    /// Reads every OTP QR code in an image, for "add from a picture".
    /// </summary>
    /// <remarks>
    /// Needs the core built with the <c>qr-image</c> feature; without it the
    /// call fails with an unknown-method error.
    /// </remarks>
    internal static string[] DecodeQrImage(byte[] image) =>
        MfaCore.Call<string[]>("decode_qr_image", new { image });

    internal static string LibraryVersion() => MfaCore.Call<string>("library_version");
}
