using Windows.Security.Credentials.UI;

namespace MFA.Platform;

/// <summary>
/// The app-lock gate: Windows Hello, falling back to the account password.
/// </summary>
/// <remarks>
/// This is <c>mfa_core::platform::BiometricAuth</c> on Windows.
/// <see cref="UserConsentVerifier"/> covers face, fingerprint and the Hello
/// PIN, and ends at the account password if none of those is set up — so the
/// user always has a way in, and the app does not need a PIN of its own to be
/// the fallback. Same conclusion as on Apple and Android, and the same reason
/// the vault's PIN is a re-authentication step here rather than the unlock.
/// </remarks>
internal static class WindowsHello
{
    internal enum Capability
    {
        /// <summary>Hello is set up: face, fingerprint or PIN.</summary>
        Available,

        /// <summary>The hardware is there but nothing is enrolled.</summary>
        NotEnrolled,

        /// <summary>No Hello at all; the app cannot lock.</summary>
        Unavailable,
    }

    internal enum Outcome
    {
        Succeeded,

        /// <summary>The user dismissed the prompt. Not a failure; do not nag.</summary>
        Cancelled,

        Failed,
    }

    internal static async Task<Capability> CheckAsync() =>
        await UserConsentVerifier.CheckAvailabilityAsync() switch
        {
            UserConsentVerifierAvailability.Available => Capability.Available,
            UserConsentVerifierAvailability.DeviceBusy => Capability.Available,
            UserConsentVerifierAvailability.NotConfiguredForUser => Capability.NotEnrolled,
            _ => Capability.Unavailable,
        };

    /// <summary>Prompts the user. <paramref name="reason"/> is shown by Windows.</summary>
    internal static async Task<Outcome> AuthenticateAsync(string reason) =>
        await UserConsentVerifier.RequestVerificationAsync(reason) switch
        {
            UserConsentVerificationResult.Verified => Outcome.Succeeded,
            UserConsentVerificationResult.Canceled => Outcome.Cancelled,
            // DeviceNotPresent and NotConfiguredForUser are a failure to show,
            // not a cancel: the user did not choose this.
            _ => Outcome.Failed,
        };
}
