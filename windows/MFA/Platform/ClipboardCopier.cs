using Windows.ApplicationModel.DataTransfer;

namespace MFA.Platform;

/// <summary>
/// Copying a code, and clearing it again (spec §4).
/// </summary>
/// <remarks>
/// This is <c>mfa_core::platform::Clipboard</c> on Windows. Two things worth
/// knowing:
/// <list type="bullet">
/// <item>The code is kept out of clipboard history and out of cloud roaming.
/// Without that, Windows would keep it after we had cleared it, and sync it to
/// the user's other machines.</item>
/// <item>Clearing is ours to do, with a timer, and only if nothing else has
/// been copied since — wiping something the user copied afterwards would be
/// worse than leaving the code. The timer dies with the process, so
/// <see cref="Copy"/> reports whether the clearing can honestly be
/// promised.</item>
/// </list>
/// </remarks>
internal static class ClipboardCopier
{
    /// <summary>Returns whether the code will really be cleared.</summary>
    internal static bool Copy(string code, uint clearAfterSeconds)
    {
        var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
        package.SetText(code);

        Clipboard.SetContentWithOptions(package, new ClipboardContentOptions
        {
            // Not in history, not roamed to the user's other machines.
            IsAllowedInHistory = false,
            IsRoamable = false,
        });
        Clipboard.Flush();

        _ = ClearLaterAsync(code, clearAfterSeconds);

        // Best effort: the timer does not survive the app being closed.
        return false;
    }

    private static async Task ClearLaterAsync(string code, uint seconds)
    {
        await Task.Delay(TimeSpan.FromSeconds(seconds));

        try
        {
            var current = await Clipboard.GetContent().GetTextAsync();
            if (current != code) return;
            Clipboard.Clear();
        }
        catch (Exception)
        {
            // The clipboard can be locked by another process, or hold
            // something that is not text. Either way there is nothing to do
            // and nothing worth telling the user.
        }
    }
}
