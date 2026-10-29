namespace MFA.Platform;

/// <summary>
/// Where the encrypted vault file lives, and how it is written.
/// </summary>
/// <remarks>
/// This is <c>mfa_core::platform::VaultStorage</c> on Windows. The write is
/// atomic because a vault truncated half way through is a vault that no longer
/// decrypts, and the accounts in it are not recoverable.
/// </remarks>
internal sealed class VaultStore
{
    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "MFA",
        "vault.mfa");

    internal bool Exists => File.Exists(_path);

    internal byte[]? Read() => Exists ? File.ReadAllBytes(_path) : null;

    internal void Write(byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

        var temporary = _path + ".tmp";
        File.WriteAllBytes(temporary, bytes);

        if (Exists)
        {
            // File.Replace is the atomic swap; it also keeps the original as a
            // backup until the call returns, which File.Move does not.
            File.Replace(temporary, _path, destinationBackupFileName: null);
        }
        else
        {
            File.Move(temporary, _path);
        }
    }

    internal void DeleteFile()
    {
        if (Exists) File.Delete(_path);
    }
}
