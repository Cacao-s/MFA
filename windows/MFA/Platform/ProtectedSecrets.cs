using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MFA.Platform;

/// <summary>
/// The keys the core needs, protected by DPAPI.
/// </summary>
/// <remarks>
/// This is <c>mfa_core::platform::SecureStore</c> on Windows. DPAPI with
/// <see cref="DataProtectionScope.CurrentUser"/> ties the ciphertext to the
/// signed-in Windows account: another account on the same machine cannot
/// unprotect it, and a copy of the file taken to another machine is useless.
/// <para/>
/// Each entry gets its own entropy, derived from its name. That is not a
/// secret — it is in this source — and it is not meant to be: it stops a
/// vault key being swapped for a sync key by someone who can edit the file,
/// which is a mistake worth making impossible rather than an attack worth
/// defending.
/// <para/>
/// Unlike the Keychain on Apple and the Keystore on Android, DPAPI is not
/// hardware-backed and is unlocked whenever the user is signed in. So on
/// Windows the lock (see <see cref="WindowsHello"/>) is what stands between a
/// signed-in session and the codes, and the vault file is only as safe as the
/// Windows account. That is worth being honest about rather than implying
/// parity.
/// </remarks>
internal static class ProtectedSecrets
{
    internal const string VaultKeyName = "vault-data-key";
    internal const string SyncKeyName = "sync-key";

    private static readonly string StorePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "MFA",
        "secrets.json");

    internal static byte[]? Load(string name)
    {
        var stored = ReadAll();
        if (!stored.TryGetValue(name, out var encoded)) return null;

        try
        {
            return ProtectedData.Unprotect(
                Convert.FromBase64String(encoded),
                Entropy(name),
                DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            // The entry cannot be unprotected: a different Windows account, a
            // copied file, or a corrupted profile. There is nothing to
            // recover, and the caller has to say so rather than retry.
            return null;
        }
    }

    internal static void Store(string name, byte[] value)
    {
        var protectedValue = ProtectedData.Protect(
            value, Entropy(name), DataProtectionScope.CurrentUser);

        var stored = ReadAll();
        stored[name] = Convert.ToBase64String(protectedValue);
        WriteAll(stored);
    }

    internal static void Delete(string name)
    {
        var stored = ReadAll();
        if (stored.Remove(name)) WriteAll(stored);
    }

    internal static void DeleteEverything()
    {
        if (File.Exists(StorePath)) File.Delete(StorePath);
    }

    /// <summary>A sync target's token.</summary>
    /// <remarks>
    /// Tokens live here and never in the vault: the vault's settings travel to
    /// the other devices, and a GitHub token must not.
    /// </remarks>
    internal static string? LoadToken(string targetId) =>
        Load($"token-{targetId}") is { } bytes ? Encoding.UTF8.GetString(bytes) : null;

    internal static void StoreToken(string targetId, string token) =>
        Store($"token-{targetId}", Encoding.UTF8.GetBytes(token));

    internal static void DeleteToken(string targetId) => Delete($"token-{targetId}");

    private static byte[] Entropy(string name) =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"com.zeyanlin.mfa:{name}"));

    private static Dictionary<string, string> ReadAll()
    {
        if (!File.Exists(StorePath)) return [];
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(
                File.ReadAllText(StorePath)) ?? [];
        }
        catch (Exception exception) when (exception is JsonException or IOException)
        {
            return [];
        }
    }

    private static void WriteAll(Dictionary<string, string> stored)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StorePath)!);

        // Write then replace, so an interrupted write cannot leave a file that
        // parses but has lost an entry.
        var temporary = StorePath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(stored));
        File.Move(temporary, StorePath, overwrite: true);
    }
}
