using MFA.Core;
using MFA.Platform;

namespace MFA.Sync;

/// <summary>
/// Runs one sync round over every enabled target.
/// </summary>
/// <remarks>
/// The core decides what the vault should become; this decides how the bytes
/// move. Read, merge, write — retrying a target whose revision moved while we
/// were merging, and never overwriting it, because the file is opaque
/// ciphertext that nothing can merge after the fact.
/// </remarks>
internal sealed class SyncCoordinator(VaultHandle vault, byte[] syncKey)
{
    /// <summary>
    /// How many times one target may lose the race before we leave it for the
    /// next sync. Enough for a real collision, small enough that a
    /// misbehaving server cannot spin here.
    /// </summary>
    private const int MaxAttempts = 3;

    internal sealed record Result(
        MergeSummary Summary,
        List<string> Written,
        List<(string Label, string Message)> Problems);

    /// <summary>
    /// Syncs every enabled target.
    /// </summary>
    /// <remarks>
    /// The caller seals the vault and writes it locally afterwards. This does
    /// not touch the local file, so a failed sync cannot corrupt it.
    /// </remarks>
    internal async Task<Result> RunAsync()
    {
        var summary = new MergeSummary(0, 0, 0, 0, false);
        var written = new List<string>();
        var problems = new List<(string, string)>();

        // Build the providers first, so a target with no token is reported
        // rather than silently skipped.
        var pending = new List<(SyncTargetView Target, ISyncProvider Provider)>();
        foreach (var target in vault.SyncTargets().Where(target => target.Enabled))
        {
            try
            {
                pending.Add((target, ProviderFor(target)));
            }
            catch (Exception exception)
            {
                problems.Add((target.Label, exception.Message));
            }
        }

        for (var attempt = 0; pending.Count > 0 && attempt < MaxAttempts; attempt++)
        {
            var retry = new List<(SyncTargetView, ISyncProvider)>();

            // 1. Read every target.
            var revisions = new Dictionary<string, string?>();
            var remotes = new List<RemoteFile>();
            foreach (var (target, provider) in pending)
            {
                try
                {
                    var fetched = await provider.FetchAsync(SyncFile.Vault);
                    revisions[target.Id] = fetched?.Revision;
                    remotes.Add(new RemoteFile(target.Id, fetched?.Bytes));
                }
                catch (Exception exception)
                {
                    problems.Add((target.Label, exception.Message));
                }
            }
            if (remotes.Count == 0) break;

            // 2. Merge them all at once: one round, one dedupe.
            SyncRound round;
            try
            {
                round = vault.Sync(remotes, syncKey);
            }
            catch (MfaException exception)
            {
                problems.Add(("sync", exception.Message));
                break;
            }
            summary = Add(summary, round.Summary);

            foreach (var failure in round.Failures)
            {
                var label = pending.FirstOrDefault(entry => entry.Target.Id == failure.Target)
                    .Target?.Label ?? failure.Target;
                problems.Add((label, failure.Message));
            }

            // 3. Write back to whichever targets are behind.
            foreach (var upload in round.Uploads)
            {
                var entry = pending.FirstOrDefault(candidate => candidate.Target.Id == upload.Target);
                if (entry.Target is null) continue;

                try
                {
                    revisions.TryGetValue(upload.Target, out var expected);
                    var result = await entry.Provider.PutAsync(SyncFile.Vault, upload.Bytes, expected);
                    if (result is null)
                    {
                        // Somebody wrote first. Round again against what is
                        // there now rather than overwriting it.
                        retry.Add((entry.Target, entry.Provider));
                    }
                    else
                    {
                        written.Add(entry.Target.Label);
                    }
                }
                catch (Exception exception)
                {
                    problems.Add((entry.Target.Label, exception.Message));
                }
            }

            pending = retry.Select(entry => (entry.Item1, entry.Item2)).ToList();
        }

        foreach (var (target, _) in pending)
        {
            problems.Add((target.Label,
                "Another device kept writing first. It will try again on the next sync."));
        }

        return new Result(summary, written, problems);
    }

    /// <summary>Publishes the wrapped sync key so another device can join.</summary>
    internal async Task PublishKeyFileAsync(string password)
    {
        var wrapped = Mfa.WrapSyncKey(syncKey, password);
        foreach (var target in vault.SyncTargets().Where(target => target.Enabled))
        {
            var provider = ProviderFor(target);
            var existing = await provider.FetchAsync(SyncFile.Key);
            await provider.PutAsync(SyncFile.Key, wrapped, existing?.Revision);
        }
    }

    /// <summary>Looks for the key file, for a device joining an existing set.</summary>
    internal async Task<byte[]?> FetchKeyFileAsync()
    {
        foreach (var target in vault.SyncTargets().Where(target => target.Enabled))
        {
            try
            {
                var fetched = await ProviderFor(target).FetchAsync(SyncFile.Key);
                if (fetched is not null) return fetched.Bytes;
            }
            catch (Exception)
            {
                // Try the next target: one unreachable place should not stop a
                // device joining.
            }
        }
        return null;
    }

    private static ISyncProvider ProviderFor(SyncTargetView target)
    {
        if (target.Kind == SyncKind.Folder)
        {
            if (!Directory.Exists(target.Location))
            {
                throw new SyncProblem("the folder is no longer there; choose it again");
            }
            return new FolderProvider(target.Location);
        }

        var token = ProtectedSecrets.LoadToken(target.Id);
        if (string.IsNullOrEmpty(token))
        {
            throw new SyncProblem(
                $"no token is saved for “{target.Label}”; add it again in Settings");
        }

        return new HttpProvider(
            target.Kind switch
            {
                SyncKind.GitHub => HttpProvider.Flavour.GitHub,
                SyncKind.GitLab => HttpProvider.Flavour.GitLab,
                _ => HttpProvider.Flavour.SelfHosted,
            },
            target.Location,
            token);
    }

    private static MergeSummary Add(MergeSummary total, MergeSummary round) => new(
        total.Added + round.Added,
        total.Updated + round.Updated,
        total.Deleted + round.Deleted,
        total.Deduped + round.Deduped,
        total.Changed || round.Changed);
}
