using System.Text.Json.Serialization;

namespace MFA.Core;

/// <summary>One account, ready to render.</summary>
/// <remarks>
/// <c>Code</c> and <c>RemainingSecs</c> are for the moment the caller asked
/// about, so the list is a pure function of the vault and the clock.
/// </remarks>
internal sealed record AccountView(
    string Id,
    string? Issuer,
    string Account,
    string DisplayName,
    string Code,
    uint RemainingSecs,
    uint Period,
    byte Digits,
    string Algorithm,
    string? Note);

/// <summary>
/// What a scanned or pasted URI holds, for a confirmation screen.
/// Deliberately without the secret.
/// </summary>
internal sealed record UriPreview(
    string? Issuer,
    string Account,
    string DisplayName,
    string Algorithm,
    byte Digits,
    uint Period);

/// <summary>A manually typed account.</summary>
internal sealed record AccountDraft(
    string? Issuer,
    string Account,
    string Secret,
    string Algorithm = "SHA1",
    byte Digits = 6,
    uint Period = 30);

/// <summary>What a merge, an import or a sync round changed.</summary>
internal sealed record MergeSummary(
    uint Added,
    uint Updated,
    uint Deleted,
    uint Deduped,
    bool Changed);

/// <summary>How far through a multi-QR Google Authenticator export we are.</summary>
internal sealed record MigrationProgress(
    uint Scanned,
    uint Expected,
    bool Complete,
    int[] Missing);

internal sealed record SkippedAccountView(string DisplayName, string Reason);

internal sealed record ImportResult(MergeSummary Summary, SkippedAccountView[] Skipped);

internal sealed record BackupInfo(byte Format, uint MemoryKib, uint Iterations, uint Lanes);

internal sealed record LockConfig(
    bool BiometricEnabled,
    uint BackgroundTimeoutSecs,
    bool HasPin);

[JsonConverter(typeof(JsonStringEnumConverter))]
internal enum SortMode { Manual, IssuerAsc }

internal sealed record Preferences(uint ClipboardClearSecs, SortMode Sort);

[JsonConverter(typeof(JsonStringEnumConverter))]
internal enum SyncKind { Folder, GitHub, GitLab, Server }

/// <summary>
/// One configured sync target. Credentials are not here and never travel:
/// they belong in this machine's own protected storage.
/// </summary>
internal sealed record SyncTargetView(
    string Id,
    SyncKind Kind,
    string Label,
    string Location,
    bool Enabled);

/// <summary>A target's file as the platform fetched it.</summary>
internal sealed record RemoteFile(string Target, byte[]? Bytes);

internal sealed record UploadRequest(string Target, byte[] Bytes);

internal sealed record SyncFailure(string Target, string Message);

internal sealed record SyncRound(
    MergeSummary Summary,
    UploadRequest[] Uploads,
    SyncFailure[] Failures);
