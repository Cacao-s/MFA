using System.ComponentModel;
using System.Runtime.CompilerServices;
using MFA.Core;
using MFA.Platform;
using MFA.Sync;

namespace MFA;

/// <summary>
/// The one piece of state the whole app reads.
/// </summary>
/// <remarks>
/// It owns the open vault, and nothing else holds a <see cref="VaultHandle"/>,
/// so there is a single place where "change something, then seal and write"
/// happens. Every mutation goes through <see cref="Mutate"/>, which means a
/// change can never be left unsaved by a code path that forgot.
/// </remarks>
internal sealed class AppModel : INotifyPropertyChanged
{
    internal enum Phase { Loading, NeedsSetup, Locked, Unlocked }

    internal sealed record Notice(string Title, string Body);

    private readonly VaultStore _store = new();
    private VaultHandle? _vault;
    private DateTimeOffset? _leftForeground;

    public event PropertyChangedEventHandler? PropertyChanged;

    private Phase _current = Phase.Loading;
    internal Phase Current
    {
        get => _current;
        private set => Set(ref _current, value);
    }

    private IReadOnlyList<AccountView> _accounts = [];
    internal IReadOnlyList<AccountView> Accounts
    {
        get => _accounts;
        private set => Set(ref _accounts, value);
    }

    private string _query = "";
    internal string Query
    {
        get => _query;
        set { Set(ref _query, value); Refresh(); }
    }

    private string? _status;
    internal string? Status
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    private Notice? _pendingNotice;

    /// <summary>
    /// Something to tell the user. The window clears it once it has been
    /// shown, so setting it again shows it again.
    /// </summary>
    internal Notice? PendingNotice
    {
        get => _pendingNotice;
        set => Set(ref _pendingNotice, value);
    }

    private bool _isSyncing;
    internal bool IsSyncing
    {
        get => _isSyncing;
        private set => Set(ref _isSyncing, value);
    }

    internal bool HasSyncKey => ProtectedSecrets.Load(ProtectedSecrets.SyncKeyName) is not null;

    /// <summary>
    /// Whether the app locks, and after how long.
    /// </summary>
    /// <remarks>
    /// Mirrored outside the vault because the vault cannot be read until the
    /// app is unlocked, and deciding whether to show the lock screen is the
    /// thing that happens first. Neither value is secret.
    /// </remarks>
    private static bool IsLockEnabled
    {
        get => LocalSetting.GetBool("lock-enabled", true);
        set => LocalSetting.SetBool("lock-enabled", value);
    }

    private static int BackgroundTimeoutSeconds
    {
        get => LocalSetting.GetInt("lock-timeout", 30);
        set => LocalSetting.SetInt("lock-timeout", value);
    }

    // --- lifecycle -------------------------------------------------------

    /// <summary>Works out whether this is a first run, and whether to lock.</summary>
    internal void Start()
    {
        if (!_store.Exists)
        {
            Current = Phase.NeedsSetup;
            return;
        }
        Current = IsLockEnabled ? Phase.Locked : Phase.Unlocked;
        if (Current == Phase.Unlocked) OpenVault();
    }

    /// <summary>First run: make a key, store it, and write an empty vault.</summary>
    internal void CreateVault() => Report("Could not create your vault", () =>
    {
        var key = Mfa.GenerateDataKey();
        // Store the key before sealing anything with it: the other order
        // leaves a vault file nothing can read.
        ProtectedSecrets.Store(ProtectedSecrets.VaultKeyName, key);

        var vault = VaultHandle.Create(key);
        _store.Write(vault.Seal());
        Adopt(vault);
    });

    /// <summary>Called once Windows Hello has verified the user.</summary>
    internal void OnUnlocked() => OpenVault();

    internal void Lock()
    {
        _vault?.Dispose();
        _vault = null;
        Accounts = [];
        Query = "";
        Current = Phase.Locked;
    }

    internal void EnteredBackground() => _leftForeground = DateTimeOffset.UtcNow;

    /// <summary>Re-locks if the window was away longer than the user asked.</summary>
    internal void EnteredForeground()
    {
        var left = _leftForeground;
        _leftForeground = null;
        if (left is null || Current != Phase.Unlocked || !IsLockEnabled) return;

        if ((DateTimeOffset.UtcNow - left.Value).TotalSeconds >= BackgroundTimeoutSeconds)
        {
            Lock();
        }
    }

    private void OpenVault() => Report("Could not open your vault", () =>
    {
        var key = ProtectedSecrets.Load(ProtectedSecrets.VaultKeyName);
        if (key is null)
        {
            // The file is here but the key cannot be unprotected: a different
            // Windows account, or a copied profile. The ciphertext is useless
            // now, and saying so beats an unexplained failure.
            PendingNotice = new Notice(
                "This vault cannot be opened",
                "Its key was protected for the Windows account that created it, and this is " +
                "not that account. Restore from an encrypted backup or a sync target to get " +
                "your accounts back.");
            Current = Phase.NeedsSetup;
            return;
        }

        var file = _store.Read();
        if (file is null)
        {
            Current = Phase.NeedsSetup;
            return;
        }
        Adopt(VaultHandle.Open(key, file));
    });

    private void Adopt(VaultHandle vault)
    {
        _vault = vault;
        MirrorLockSettings();
        Current = Phase.Unlocked;
        Refresh();
    }

    private void MirrorLockSettings()
    {
        if (_vault is null) return;
        var config = _vault.LockConfig();
        IsLockEnabled = config.BiometricEnabled;
        BackgroundTimeoutSeconds = (int)config.BackgroundTimeoutSecs;
    }

    /// <summary>
    /// Recomputes the list. Called once a second by the window's timer, so the
    /// codes and countdown rings stay right without every row owning a timer.
    /// </summary>
    internal void Refresh()
    {
        if (_vault is null) return;
        var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        try
        {
            Accounts = string.IsNullOrWhiteSpace(Query)
                ? _vault.Accounts(now)
                : _vault.Search(Query, now);
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice("Could not read your accounts", exception.Message);
        }
    }

    // --- mutations -------------------------------------------------------

    private static long NowMs => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    private void Mutate(string title, Action<VaultHandle> change)
    {
        if (_vault is null) return;
        Report(title, () =>
        {
            change(_vault);
            _store.Write(_vault.Seal());
            MirrorLockSettings();
            Refresh();
        });
    }

    /// <summary>Adds a scanned or pasted URI. Returns whether it was new.</summary>
    internal bool Add(string uri)
    {
        if (_vault is null) return false;

        string? existing = null;
        try
        {
            existing = _vault.DuplicateOfUri(uri);
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice("Could not add that account", exception.Message);
            return false;
        }

        Mutate("Could not add that account", vault => vault.AddUri(uri, NowMs));
        Show(existing is null ? "Added" : "You already had that account");
        return existing is null;
    }

    internal void Add(AccountDraft draft)
    {
        Mutate("Could not add that account", vault => vault.AddManual(draft, NowMs));
        Show("Added");
    }

    internal void Delete(string id) =>
        Mutate("Could not delete that account", vault => vault.Delete(id, NowMs));

    internal void SetNote(string id, string? note) =>
        Mutate("Could not save the note", vault => vault.SetNote(id, note, NowMs));

    internal void Rename(string id, string? issuer, string account) =>
        Mutate("Could not rename that account", vault => vault.Rename(id, issuer, account, NowMs));

    internal void Reorder(IEnumerable<string> ids) =>
        Mutate("Could not reorder", vault => vault.Reorder(ids, NowMs));

    internal void Copy(AccountView account)
    {
        var seconds = _vault?.Preferences().ClipboardClearSecs ?? 30;
        ClipboardCopier.Copy(account.Code, seconds);
        Show("Copied");
    }

    /// <summary>
    /// The URI for a QR code to move the account elsewhere.
    /// <b>This contains the secret</b>, which is why it is a separate call.
    /// </summary>
    internal string? ExportUri(string id)
    {
        try
        {
            return _vault?.AccountUri(id);
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice("Could not read that account", exception.Message);
            return null;
        }
    }

    // --- settings --------------------------------------------------------

    internal LockConfig? LockConfig() => _vault?.LockConfig();
    internal Preferences? Preferences() => _vault?.Preferences();
    internal SyncTargetView[] SyncTargets() => _vault?.SyncTargets() ?? [];

    internal void SetLockConfig(LockConfig config) =>
        Mutate("Could not save the lock settings", vault => vault.SetLockConfig(config, NowMs));

    internal void SetPreferences(Preferences preferences) =>
        Mutate("Could not save your settings", vault => vault.SetPreferences(preferences, NowMs));

    internal void SetPin(string pin)
    {
        Mutate("Could not set the PIN", vault => vault.SetPin(pin, NowMs));
        Show("PIN set");
    }

    internal void ClearPin() => Mutate("Could not remove the PIN", vault => vault.ClearPin(NowMs));

    internal bool VerifyPin(string pin) => _vault?.VerifyPin(pin) ?? false;

    internal void UpsertSyncTarget(SyncTargetView target, string? token)
    {
        if (_vault is null) return;
        Report("Could not save that sync target", () =>
        {
            var id = _vault.UpsertSyncTarget(target, NowMs);
            _store.Write(_vault.Seal());
            if (!string.IsNullOrEmpty(token)) ProtectedSecrets.StoreToken(id, token);
            Refresh();
        });
    }

    internal void RemoveSyncTarget(string id)
    {
        Mutate("Could not remove that sync target", vault => vault.RemoveSyncTarget(id, NowMs));
        ProtectedSecrets.DeleteToken(id);
    }

    // --- backup ----------------------------------------------------------

    internal byte[]? ExportBackup(string password)
    {
        try
        {
            return _vault?.ExportBackup(password);
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice("Could not export", exception.Message);
            return null;
        }
    }

    internal void ImportBackup(byte[] file, string password)
    {
        if (_vault is null) return;
        try
        {
            var summary = _vault.ImportBackup(file, password);
            // Only write once the import succeeded: the core leaves the vault
            // untouched on a wrong password, and so should the file.
            _store.Write(_vault.Seal());
            Refresh();
            Show(summary.Added == 0
                ? "Nothing new in that backup"
                : $"Restored {summary.Added} account{(summary.Added == 1 ? "" : "s")}");
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice("Could not import", exception.Message);
        }
    }

    // --- migration -------------------------------------------------------

    internal void ImportMigration(IReadOnlyList<string> uris)
    {
        if (_vault is null) return;
        try
        {
            var result = _vault.ImportMigration(uris, NowMs);
            _store.Write(_vault.Seal());
            Refresh();

            if (result.Skipped.Length == 0)
            {
                Show($"Imported {result.Summary.Added} " +
                     $"account{(result.Summary.Added == 1 ? "" : "s")}");
            }
            else
            {
                // Never silent: a user told nothing will assume everything
                // came across and find out when they cannot log in.
                PendingNotice = new Notice(
                    $"Imported {result.Summary.Added}, skipped {result.Skipped.Length}",
                    string.Join("\n", result.Skipped.Select(s => $"{s.DisplayName} — {s.Reason}")));
            }
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice("Could not import", exception.Message);
        }
    }

    // --- sync ------------------------------------------------------------

    internal async Task SyncNowAsync()
    {
        if (_vault is null || IsSyncing) return;

        var key = ProtectedSecrets.Load(ProtectedSecrets.SyncKeyName);
        if (key is null)
        {
            PendingNotice = new Notice("Sync is not set up", "Add a sync target in Settings first.");
            return;
        }

        IsSyncing = true;
        try
        {
            var result = await new SyncCoordinator(_vault, key).RunAsync();
            _store.Write(_vault.Seal());
            Refresh();

            if (result.Problems.Count > 0)
            {
                PendingNotice = new Notice("Sync had a problem",
                    string.Join("\n", result.Problems.Select(p => $"{p.Label}: {p.Message}")));
            }
            else
            {
                Show(SummaryLine(result.Summary));
            }
        }
        catch (Exception exception)
        {
            PendingNotice = new Notice("Sync failed", exception.Message);
        }
        finally
        {
            IsSyncing = false;
        }
    }

    internal void CreateSyncSet() => Report("Could not set up sync", () =>
    {
        ProtectedSecrets.Store(ProtectedSecrets.SyncKeyName, Mfa.NewSyncKey());
        Show("Sync set up on this device");
    });

    internal async Task<string?> PublishKeyFileAsync(string password)
    {
        if (_vault is null) return "The vault is not open.";
        var key = ProtectedSecrets.Load(ProtectedSecrets.SyncKeyName);
        if (key is null) return "Sync is not set up on this device yet.";

        try
        {
            await new SyncCoordinator(_vault, key).PublishKeyFileAsync(password);
            Show("Key file published");
            return null;
        }
        catch (Exception exception)
        {
            return exception.Message;
        }
    }

    internal async Task<string?> JoinSyncSetAsync(string password)
    {
        if (_vault is null) return "The vault is not open.";

        try
        {
            // Any key will do to build the providers; only the targets and
            // their tokens matter for reading the key file.
            var placeholder = ProtectedSecrets.Load(ProtectedSecrets.SyncKeyName) ?? new byte[32];
            var keyFile = await new SyncCoordinator(_vault, placeholder).FetchKeyFileAsync();
            if (keyFile is null)
            {
                return "No key file was found. Publish one from the device that already syncs.";
            }

            ProtectedSecrets.Store(ProtectedSecrets.SyncKeyName,
                                   Mfa.UnwrapSyncKey(keyFile, password));
            Show("This device has joined");
            return null;
        }
        catch (Exception exception)
        {
            return exception.Message;
        }
    }

    private static string SummaryLine(MergeSummary summary)
    {
        if (!summary.Changed) return "Already up to date";

        var parts = new List<string>();
        if (summary.Added > 0) parts.Add($"{summary.Added} added");
        if (summary.Updated > 0) parts.Add($"{summary.Updated} updated");
        if (summary.Deleted > 0) parts.Add($"{summary.Deleted} removed");
        if (summary.Deduped > 0)
        {
            parts.Add($"{summary.Deduped} duplicate{(summary.Deduped == 1 ? "" : "s")} merged");
        }
        return parts.Count == 0 ? "Synced" : "Synced: " + string.Join(", ", parts);
    }

    // --- reset -----------------------------------------------------------

    /// <summary>
    /// Deletes everything on this machine.
    /// </summary>
    /// <remarks>
    /// Takes the keys as well as the file: leaving them behind would mean a
    /// recovered file could still be read.
    /// </remarks>
    internal void ResetEverything()
    {
        Lock();
        _store.DeleteFile();
        ProtectedSecrets.DeleteEverything();
        Current = Phase.NeedsSetup;
    }

    // --- reporting -------------------------------------------------------

    private void Show(string text)
    {
        Status = text;
        _ = ClearStatusLaterAsync(text);
    }

    private async Task ClearStatusLaterAsync(string text)
    {
        await Task.Delay(TimeSpan.FromSeconds(3));
        if (Status == text) Status = null;
    }

    /// <summary>Runs a block, turning any failure into something readable.</summary>
    private void Report(string title, Action block)
    {
        try
        {
            block();
        }
        catch (MfaException exception)
        {
            PendingNotice = new Notice(title, exception.Message);
        }
        catch (Exception exception)
        {
            PendingNotice = new Notice(title, exception.Message);
        }
    }

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

/// <summary>
/// The two non-secret settings the app needs before the vault is open.
/// </summary>
/// <remarks>
/// A plain file rather than <c>ApplicationData</c>, because the app has to run
/// unpackaged as well as packaged and the WinRT settings API is not available
/// unpackaged.
/// </remarks>
internal static class LocalSetting
{
    private static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "MFA",
        "settings.json");

    internal static bool GetBool(string name, bool fallback) =>
        Read().TryGetValue(name, out var value) && bool.TryParse(value, out var parsed)
            ? parsed : fallback;

    internal static void SetBool(string name, bool value) => Write(name, value.ToString());

    internal static int GetInt(string name, int fallback) =>
        Read().TryGetValue(name, out var value) && int.TryParse(value, out var parsed)
            ? parsed : fallback;

    internal static void SetInt(string name, int value) => Write(name, value.ToString());

    private static Dictionary<string, string> Read()
    {
        if (!File.Exists(Path)) return [];
        try
        {
            return System.Text.Json.JsonSerializer
                .Deserialize<Dictionary<string, string>>(File.ReadAllText(Path)) ?? [];
        }
        catch (Exception)
        {
            return [];
        }
    }

    private static void Write(string name, string value)
    {
        var settings = Read();
        settings[name] = value;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        File.WriteAllText(Path, System.Text.Json.JsonSerializer.Serialize(settings));
    }
}
